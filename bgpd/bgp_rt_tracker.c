/*
 * bgp_rt_tracker.c — Per-peer Route Target tracker for EVPN
 *
 * Hooks into bgp_route_update to learn which RTs each peer advertises.
 * Maintains a per-peer hash of RT sets with refcounts, logs transitions
 * (peer joins/leaves an RT) when debug is enabled.
 *
 * RTs are classified into two buckets:
 *   - VPC RTs:     local-admin >= vpc_threshold (default 1001)
 *   - General RTs: local-admin <  vpc_threshold
 *
 * Copyright (C) 2026 Nick Bouliane
 */

#include <zebra.h>

#include "command.h"
#include "memory.h"
#include "log.h"
#include "vty.h"
#include "hash.h"
#include "jhash.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_rt_tracker.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_evpn_private.h"

DEFINE_MGROUP(RT_TRACKER, "RT Tracker");
DEFINE_MTYPE_STATIC(RT_TRACKER, RT_TRACKER_ENTRY, "RT tracker peer entry");
DEFINE_MTYPE_STATIC(RT_TRACKER, RT_TRACKER_SLOTS, "RT tracker RT slots");

/* ===================================================================
 * Configuration
 * =================================================================== */

static bool rt_tracker_debug;
static uint32_t rt_tracker_vpc_threshold = 1001;
static bool rt_tracker_cli_installed;

/* ===================================================================
 * Data Structures
 * =================================================================== */

struct rt_slot {
	uint32_t rt_local_admin;	/* e.g. 1002 */
	uint32_t rt_global_admin;	/* e.g. 182 (AS or IP-derived) */
	uint32_t refcount;		/* number of routes carrying this RT */
};

struct peer_rt_entry {
	struct peer *peer;

	/* VPC RTs (local-admin >= vpc_threshold) */
	uint16_t vpc_count;
	uint16_t vpc_alloc;
	struct rt_slot *vpc_rts;

	/* General RTs (local-admin < vpc_threshold) */
	uint16_t gen_count;
	uint16_t gen_alloc;
	struct rt_slot *gen_rts;

	time_t first_seen;
};

static struct hash *peer_rt_hash;

/* ===================================================================
 * Hash helpers
 * =================================================================== */

static unsigned int peer_rt_hash_key(const void *p)
{
	const struct peer_rt_entry *e = p;

	return jhash_1word((uintptr_t)e->peer, 0x52545452);
}

static bool peer_rt_hash_cmp(const void *a, const void *b)
{
	const struct peer_rt_entry *ea = a;
	const struct peer_rt_entry *eb = b;

	return ea->peer == eb->peer;
}

static void *peer_rt_hash_alloc(void *data)
{
	struct peer_rt_entry *src = data;
	struct peer_rt_entry *entry;

	entry = XCALLOC(MTYPE_RT_TRACKER_ENTRY, sizeof(*entry));
	entry->peer = src->peer;
	entry->first_seen = monotime(NULL);
	return entry;
}

static struct peer_rt_entry *peer_rt_lookup(struct peer *peer, bool create)
{
	struct peer_rt_entry lookup = { .peer = peer };

	if (create)
		return hash_get(peer_rt_hash, &lookup, peer_rt_hash_alloc);
	else
		return hash_lookup(peer_rt_hash, &lookup);
}

/* ===================================================================
 * Sorted RT slot array operations (binary search + insert)
 * =================================================================== */

static struct rt_slot *rt_slot_find(struct rt_slot *slots, uint16_t count,
				    uint32_t rt_local_admin, int *pos)
{
	int lo = 0, hi = count - 1;

	while (lo <= hi) {
		int mid = (lo + hi) / 2;

		if (slots[mid].rt_local_admin == rt_local_admin) {
			if (pos)
				*pos = mid;
			return &slots[mid];
		}
		if (slots[mid].rt_local_admin < rt_local_admin)
			lo = mid + 1;
		else
			hi = mid - 1;
	}
	if (pos)
		*pos = lo;
	return NULL;
}

static void rt_slot_insert(struct rt_slot **slots, uint16_t *count,
			   uint16_t *alloc, int pos, uint32_t rt_local_admin,
			   uint32_t rt_global_admin)
{
	if (*count >= *alloc) {
		*alloc = *alloc ? *alloc * 2 : 4;
		*slots = XREALLOC(MTYPE_RT_TRACKER_SLOTS, *slots,
				  *alloc * sizeof(struct rt_slot));
	}

	/* shift right to make room */
	if (pos < *count)
		memmove(&(*slots)[pos + 1], &(*slots)[pos],
			(*count - pos) * sizeof(struct rt_slot));

	(*slots)[pos].rt_local_admin = rt_local_admin;
	(*slots)[pos].rt_global_admin = rt_global_admin;
	(*slots)[pos].refcount = 1;
	(*count)++;
}

static void rt_slot_remove(struct rt_slot *slots, uint16_t *count, int pos)
{
	if (pos < *count - 1)
		memmove(&slots[pos], &slots[pos + 1],
			(*count - pos - 1) * sizeof(struct rt_slot));
	(*count)--;
}

/* ===================================================================
 * RT extraction from ecommunity
 *
 * RT layout in ecommunity_val (8 bytes):
 *   ENCODE_AS  (0x00): [type][subtype][AS:2bytes][val:4bytes]
 *   ENCODE_IP  (0x01): [type][subtype][IP:4bytes][val:2bytes]
 *   ENCODE_AS4 (0x02): [type][subtype][AS:4bytes][val:2bytes]
 *
 * We extract:
 *   - global_admin: the AS or IP part
 *   - local_admin:  the numeric value (the VNI-related part)
 * =================================================================== */

struct rt_parsed {
	uint32_t global_admin;
	uint32_t local_admin;
};

static bool parse_rt_from_ecom_val(const uint8_t *pnt, struct rt_parsed *out)
{
	uint8_t type = pnt[0] & ~ECOMMUNITY_FLAG_NON_TRANSITIVE;
	uint8_t sub_type = pnt[1];

	if (sub_type != ECOMMUNITY_ROUTE_TARGET)
		return false;

	switch (type) {
	case ECOMMUNITY_ENCODE_AS:
		out->global_admin = (pnt[2] << 8) | pnt[3];
		out->local_admin = ((uint32_t)pnt[4] << 24) |
				   ((uint32_t)pnt[5] << 16) |
				   ((uint32_t)pnt[6] << 8) | pnt[7];
		return true;
	case ECOMMUNITY_ENCODE_IP:
		out->global_admin = ((uint32_t)pnt[2] << 24) |
				    ((uint32_t)pnt[3] << 16) |
				    ((uint32_t)pnt[4] << 8) | pnt[5];
		out->local_admin = (pnt[6] << 8) | pnt[7];
		return true;
	case ECOMMUNITY_ENCODE_AS4:
		out->global_admin = ((uint32_t)pnt[2] << 24) |
				    ((uint32_t)pnt[3] << 16) |
				    ((uint32_t)pnt[4] << 8) | pnt[5];
		out->local_admin = (pnt[6] << 8) | pnt[7];
		return true;
	}
	return false;
}

/* ===================================================================
 * Core logic: process one RT for a peer (announce or withdraw)
 * =================================================================== */

static void rt_tracker_process_rt(struct peer_rt_entry *entry,
				  struct peer *peer,
				  const struct rt_parsed *rt,
				  bool is_announce)
{
	struct rt_slot **slots;
	uint16_t *count, *alloc;
	const char *bucket_name;
	struct rt_slot *slot;
	int pos;

	if (rt->local_admin >= rt_tracker_vpc_threshold) {
		slots = &entry->vpc_rts;
		count = &entry->vpc_count;
		alloc = &entry->vpc_alloc;
		bucket_name = "VPC";
	} else {
		slots = &entry->gen_rts;
		count = &entry->gen_count;
		alloc = &entry->gen_alloc;
		bucket_name = "general";
	}

	slot = rt_slot_find(*slots, *count, rt->local_admin, &pos);

	if (is_announce) {
		if (slot) {
			slot->refcount++;
		} else {
			rt_slot_insert(slots, count, alloc, pos,
				       rt->local_admin, rt->global_admin);
			if (rt_tracker_debug)
				zlog_debug("RT-TRACKER: peer %s joined %s RT %u:%u",
					   peer->host, bucket_name,
					   rt->global_admin,
					   rt->local_admin);
		}
	} else {
		/* withdraw */
		if (!slot)
			return;
		slot->refcount--;
		if (slot->refcount == 0) {
			if (rt_tracker_debug)
				zlog_debug("RT-TRACKER: peer %s left %s RT %u:%u",
					   peer->host, bucket_name,
					   rt->global_admin,
					   rt->local_admin);
			rt_slot_remove(*slots, count, pos);
		}
	}
}

/* ===================================================================
 * Hook: bgp_route_update
 * =================================================================== */

static int rt_tracker_route_update(struct bgp *bgp, afi_t afi, safi_t safi,
				   struct bgp_dest *bn,
				   struct bgp_path_info *old_route,
				   struct bgp_path_info *new_route)
{
	const struct prefix *pfx;
	const struct prefix_evpn *evp;
	struct bgp_path_info *route;
	struct ecommunity *ecom;
	struct peer_rt_entry *entry;
	bool is_announce;
	uint32_t i;

	if (afi != AFI_L2VPN || safi != SAFI_EVPN)
		return 0;

	if (!peer_rt_hash)
		return 0;

	is_announce = (new_route != NULL && old_route == NULL);
	if (!is_announce && !(old_route != NULL && new_route == NULL))
		return 0;

	pfx = bgp_dest_get_prefix(bn);
	evp = (const struct prefix_evpn *)pfx;

	/* Only track type-5 (IP prefix) routes */
	if (evp->prefix.route_type != BGP_EVPN_IP_PREFIX_ROUTE)
		return 0;

	route = is_announce ? new_route : old_route;

	/* Skip self-originated */
	if (route->peer == bgp->peer_self)
		return 0;

	if (!route->attr)
		return 0;

	ecom = bgp_attr_get_ecommunity(route->attr);
	if (!ecom)
		return 0;

	entry = peer_rt_lookup(route->peer, is_announce);
	if (!entry)
		return 0;

	/* Walk all extended communities, process each RT */
	for (i = 0; i < ecom->size; i++) {
		const uint8_t *pnt = ecom->val + (i * ecom->unit_size);
		struct rt_parsed rt;

		if (!parse_rt_from_ecom_val(pnt, &rt))
			continue;

		rt_tracker_process_rt(entry, route->peer, &rt, is_announce);
	}

	return 0;
}

/* ===================================================================
 * Hook: peer_status_changed — cleanup on peer down
 * =================================================================== */

static int rt_tracker_peer_status(struct peer *peer)
{
	struct peer_rt_entry *entry;

	if (!peer_rt_hash)
		return 0;

	/* Only act on peer going down */
	if (peer_established(peer->connection))
		return 0;

	entry = peer_rt_lookup(peer, false);
	if (!entry)
		return 0;

	if (rt_tracker_debug) {
		zlog_debug("RT-TRACKER: peer %s down, had %u VPC RTs, %u general RTs",
			   peer->host, entry->vpc_count, entry->gen_count);
	}

	/* Remove from hash and free */
	hash_release(peer_rt_hash, entry);
	XFREE(MTYPE_RT_TRACKER_SLOTS, entry->vpc_rts);
	XFREE(MTYPE_RT_TRACKER_SLOTS, entry->gen_rts);
	XFREE(MTYPE_RT_TRACKER_ENTRY, entry);

	return 0;
}

/* ===================================================================
 * Show commands
 * =================================================================== */

static void rt_tracker_show_entry(struct vty *vty, struct peer_rt_entry *entry,
				  bool detail)
{
	char uptime[BGP_UPTIME_LEN];
	uint16_t i;

	peer_uptime(entry->first_seen, uptime, sizeof(uptime), false, NULL);

	vty_out(vty, "  Peer %s (tracked since %s)\n",
		entry->peer->host, uptime);

	if (entry->vpc_count > 0) {
		vty_out(vty, "    VPC RTs:");
		for (i = 0; i < entry->vpc_count; i++) {
			struct rt_slot *s = &entry->vpc_rts[i];

			if (detail)
				vty_out(vty, " %u:%u(%u routes)",
					s->rt_global_admin, s->rt_local_admin,
					s->refcount);
			else
				vty_out(vty, " %u:%u", s->rt_global_admin,
					s->rt_local_admin);
		}
		vty_out(vty, "\n");
	}

	if (entry->gen_count > 0) {
		vty_out(vty, "    General RTs:");
		for (i = 0; i < entry->gen_count; i++) {
			struct rt_slot *s = &entry->gen_rts[i];

			if (detail)
				vty_out(vty, " %u:%u(%u routes)",
					s->rt_global_admin, s->rt_local_admin,
					s->refcount);
			else
				vty_out(vty, " %u:%u", s->rt_global_admin,
					s->rt_local_admin);
		}
		vty_out(vty, "\n");
	}

	if (entry->vpc_count == 0 && entry->gen_count == 0)
		vty_out(vty, "    No RTs tracked\n");
}

struct rt_tracker_show_ctx {
	struct vty *vty;
	bool detail;
	uint32_t count;
};

static void rt_tracker_show_iter(struct hash_bucket *hb, void *arg)
{
	struct peer_rt_entry *entry = hb->data;
	struct rt_tracker_show_ctx *ctx = arg;

	rt_tracker_show_entry(ctx->vty, entry, ctx->detail);
	ctx->count++;
}

DEFUN(show_rt_tracker,
      show_rt_tracker_cmd,
      "show rt-tracker [detail]",
      SHOW_STR
      "Per-peer Route Target tracker\n"
      "Show route counts per RT\n")
{
	struct rt_tracker_show_ctx ctx = {
		.vty = vty,
		.detail = (argc > 2),
		.count = 0,
	};

	if (!peer_rt_hash) {
		vty_out(vty, "RT tracker not initialized\n");
		return CMD_SUCCESS;
	}

	vty_out(vty, "RT Tracker (VPC threshold: local-admin >= %u)\n",
		rt_tracker_vpc_threshold);
	hash_iterate(peer_rt_hash, rt_tracker_show_iter, &ctx);
	vty_out(vty, "Total: %u tracked peers\n", ctx.count);

	return CMD_SUCCESS;
}

DEFPY(show_rt_tracker_peer,
      show_rt_tracker_peer_cmd,
      "show rt-tracker peer A.B.C.D$addr [detail$detail]",
      SHOW_STR
      "Per-peer Route Target tracker\n"
      "Show specific peer\n"
      "Peer IPv4 address\n"
      "Show route counts per RT\n")
{
	struct peer_rt_entry *entry;
	struct peer *peer;
	struct bgp *bgp;

	if (!peer_rt_hash) {
		vty_out(vty, "RT tracker not initialized\n");
		return CMD_SUCCESS;
	}

	bgp = bgp_get_evpn();
	if (!bgp) {
		vty_out(vty, "No EVPN BGP instance\n");
		return CMD_SUCCESS;
	}

	peer = NULL;
	{
		struct peer *p;
		struct listnode *n;

		for (ALL_LIST_ELEMENTS_RO(bgp->peer, n, p)) {
			if (p->su.sa.sa_family == AF_INET &&
			    IPV4_ADDR_SAME(&p->su.sin.sin_addr, &addr)) {
				peer = p;
				break;
			}
		}
	}

	if (!peer) {
		vty_out(vty, "Peer %pI4 not found\n", &addr);
		return CMD_SUCCESS;
	}

	entry = peer_rt_lookup(peer, false);
	if (!entry) {
		vty_out(vty, "No RT tracking data for peer %pI4\n", &addr);
		return CMD_SUCCESS;
	}

	vty_out(vty, "RT Tracker (VPC threshold: local-admin >= %u)\n",
		rt_tracker_vpc_threshold);
	rt_tracker_show_entry(vty, entry, !!detail);

	return CMD_SUCCESS;
}

/* ===================================================================
 * Debug and configuration commands
 * =================================================================== */

DEFUN(rt_tracker_debug_cmd,
      rt_tracker_debug_cmd_cmd,
      "[no] debug rt-tracker",
      NO_STR
      DEBUG_STR
      "RT Tracker debugging\n")
{
	if (strmatch(argv[0]->text, "no"))
		rt_tracker_debug = false;
	else
		rt_tracker_debug = true;

	return CMD_SUCCESS;
}

DEFPY(rt_tracker_vpc_threshold_cmd,
      rt_tracker_vpc_threshold_cmd_cmd,
      "[no$no] rt-tracker vpc-threshold ![(1-16777215)$threshold]",
      NO_STR
      "RT Tracker configuration\n"
      "Local-admin threshold for VPC RT classification\n"
      "Threshold value (RTs with local-admin >= this are VPC)\n")
{
	if (no)
		rt_tracker_vpc_threshold = 1001;
	else
		rt_tracker_vpc_threshold = threshold;

	return CMD_SUCCESS;
}

/* ===================================================================
 * Module init/fini
 * =================================================================== */

static int rt_tracker_late_init(struct event_loop *tm)
{
	peer_rt_hash = hash_create(peer_rt_hash_key, peer_rt_hash_cmp,
				   "RT Tracker peer hash");

	if (!rt_tracker_cli_installed) {
		install_element(VIEW_NODE, &show_rt_tracker_cmd);
		install_element(VIEW_NODE, &show_rt_tracker_peer_cmd);
		install_element(ENABLE_NODE, &rt_tracker_debug_cmd_cmd);
		install_element(CONFIG_NODE, &rt_tracker_debug_cmd_cmd);
		install_element(CONFIG_NODE, &rt_tracker_vpc_threshold_cmd_cmd);
		rt_tracker_cli_installed = true;
	}

	zlog_info("RT-TRACKER: module loaded (vpc-threshold %u)",
		  rt_tracker_vpc_threshold);

	return 0;
}

static void rt_tracker_peer_free(struct hash_bucket *hb, void *arg)
{
	struct peer_rt_entry *entry = hb->data;

	XFREE(MTYPE_RT_TRACKER_SLOTS, entry->vpc_rts);
	XFREE(MTYPE_RT_TRACKER_SLOTS, entry->gen_rts);
	XFREE(MTYPE_RT_TRACKER_ENTRY, entry);
}

static int rt_tracker_fini(void)
{
	if (peer_rt_hash) {
		hash_iterate(peer_rt_hash, rt_tracker_peer_free, NULL);
		hash_free(peer_rt_hash);
		peer_rt_hash = NULL;
	}

	zlog_info("RT-TRACKER: module unloaded");
	return 0;
}

/* Called from bgp_init() in bgpd.c */
void bgp_rt_tracker_init(void)
{
	hook_register(frr_late_init, rt_tracker_late_init);
	hook_register(frr_fini, rt_tracker_fini);
	hook_register(bgp_route_update, rt_tracker_route_update);
	hook_register(peer_status_changed, rt_tracker_peer_status);

	zlog_info("RT-TRACKER: initialized");
}
