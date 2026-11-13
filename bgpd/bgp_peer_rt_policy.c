/*
 * bgp_peer_rt_policy.c — Per-peer RT allow-list with route-map integration
 *
 * Defines a "peer-rt-policy" data structure that maps each BGP peer
 * (by IP) to a set of allowed RT assigned-values. A route-map
 * "match peer-rt-policy NAME" clause checks that every RT on an
 * incoming route has its assigned-value in the peer's allow-list.
 *
 * The admin field (ASN/IP) of the RT is ignored — only the assigned
 * number matters for policy decisions.
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
#include "linklist.h"
#include "routemap.h"
#include "sockunion.h"

#include "frrevent.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_peer_rt_policy.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_debug.h"

#ifndef VTYSH_EXTRACT_PL
#include "bgpd/bgp_peer_rt_policy_clippy.c"
#endif

DEFINE_MGROUP(PEER_RT_POLICY, "Peer RT Policy");
DEFINE_MTYPE_STATIC(PEER_RT_POLICY, PRP_POLICY, "Peer RT policy instance");
DEFINE_MTYPE_STATIC(PEER_RT_POLICY, PRP_ENTRY, "Peer RT policy peer entry");

/* ===================================================================
 * Data structures
 * =================================================================== */

struct prp_peer_entry {
	union sockunion su;
	uint32_t *allowed;		/* sorted array of assigned-values */
	size_t allowed_count;
	size_t allowed_cap;
	struct event *t_reset;		/* scheduled reset (dedup) */
};

struct prp_policy {
	char *name;
	struct hash *peer_hash;
};

static struct list *prp_policy_list;

/* ===================================================================
 * Assigned-value helpers — sorted uint32_t array
 * =================================================================== */

/*
 * Extract the assigned-number from an 8-byte extended community value.
 * Type 0 (2-byte AS):  bytes 4-7 = 32-bit assigned number
 * Type 1 (IPv4):       bytes 6-7 = 16-bit assigned number
 * Type 2 (4-byte AS):  bytes 6-7 = 16-bit assigned number
 */
static uint32_t prp_rt_assigned_value(const uint8_t *pnt)
{
	uint8_t type = pnt[0] & ~ECOMMUNITY_FLAG_NON_TRANSITIVE;

	switch (type) {
	case ECOMMUNITY_ENCODE_AS:
		return ((uint32_t)pnt[4] << 24) | ((uint32_t)pnt[5] << 16) |
		       ((uint32_t)pnt[6] << 8) | pnt[7];
	case ECOMMUNITY_ENCODE_IP:
	case ECOMMUNITY_ENCODE_AS4:
		return ((uint32_t)pnt[6] << 8) | pnt[7];
	default:
		return UINT32_MAX;
	}
}

static bool prp_allowed_contains(const struct prp_peer_entry *entry,
				 uint32_t val)
{
	size_t lo = 0, hi = entry->allowed_count;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (entry->allowed[mid] == val)
			return true;
		if (entry->allowed[mid] < val)
			lo = mid + 1;
		else
			hi = mid;
	}
	return false;
}

static void prp_allowed_add(struct prp_peer_entry *entry, uint32_t val)
{
	size_t lo = 0, hi = entry->allowed_count;
	size_t pos;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (entry->allowed[mid] == val)
			return; /* already present */
		if (entry->allowed[mid] < val)
			lo = mid + 1;
		else
			hi = mid;
	}
	pos = lo;

	if (entry->allowed_count == entry->allowed_cap) {
		entry->allowed_cap = entry->allowed_cap
					     ? entry->allowed_cap * 2
					     : 8;
		entry->allowed =
			XREALLOC(MTYPE_PRP_ENTRY, entry->allowed,
				 entry->allowed_cap * sizeof(uint32_t));
	}

	memmove(&entry->allowed[pos + 1], &entry->allowed[pos],
		(entry->allowed_count - pos) * sizeof(uint32_t));
	entry->allowed[pos] = val;
	entry->allowed_count++;
}

static void prp_allowed_del(struct prp_peer_entry *entry, uint32_t val)
{
	size_t lo = 0, hi = entry->allowed_count;

	while (lo < hi) {
		size_t mid = lo + (hi - lo) / 2;

		if (entry->allowed[mid] == val) {
			memmove(&entry->allowed[mid], &entry->allowed[mid + 1],
				(entry->allowed_count - mid - 1) *
					sizeof(uint32_t));
			entry->allowed_count--;
			return;
		}
		if (entry->allowed[mid] < val)
			lo = mid + 1;
		else
			hi = mid;
	}
}

/* ===================================================================
 * Deferred peer reset — scheduled from route-map match on violation
 * =================================================================== */

static void prp_peer_reset_event(struct event *ev)
{
	union sockunion *su = EVENT_ARG(ev);
	struct bgp *bgp;
	struct peer *peer;

	bgp = bgp_get_evpn();
	if (!bgp)
		goto done;

	peer = peer_lookup(bgp, su);
	if (!peer)
		goto done;

	zlog_warn("PEER-RT-POLICY: resetting peer %s — unauthorized RT violation",
		  peer->host);
	peer_clear(peer, NULL);

done:
	XFREE(MTYPE_PRP_ENTRY, su);
}

/* ===================================================================
 * Peer entry hash helpers
 * =================================================================== */

static unsigned int prp_peer_hash_key(const void *p)
{
	const struct prp_peer_entry *e = p;

	return sockunion_hash(&e->su);
}

static bool prp_peer_hash_cmp(const void *a, const void *b)
{
	const struct prp_peer_entry *ea = a;
	const struct prp_peer_entry *eb = b;

	return sockunion_same(&ea->su, &eb->su);
}

static void *prp_peer_hash_alloc(void *data)
{
	struct prp_peer_entry *src = data;
	struct prp_peer_entry *entry;

	entry = XCALLOC(MTYPE_PRP_ENTRY, sizeof(*entry));
	entry->su = src->su;
	return entry;
}

static void prp_peer_entry_free(void *data)
{
	struct prp_peer_entry *entry = data;

	if (event_is_scheduled(entry->t_reset)) {
		union sockunion *su_arg = EVENT_ARG(entry->t_reset);

		event_cancel(&entry->t_reset);
		XFREE(MTYPE_PRP_ENTRY, su_arg);
	}
	XFREE(MTYPE_PRP_ENTRY, entry->allowed);
	XFREE(MTYPE_PRP_ENTRY, entry);
}

/* ===================================================================
 * Policy lookup/create/destroy
 * =================================================================== */

static struct prp_policy *prp_policy_lookup(const char *name)
{
	struct listnode *node;
	struct prp_policy *pol;

	if (!prp_policy_list)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(prp_policy_list, node, pol)) {
		if (strcmp(pol->name, name) == 0)
			return pol;
	}
	return NULL;
}

static struct prp_policy *prp_policy_get(const char *name)
{
	struct prp_policy *pol;

	pol = prp_policy_lookup(name);
	if (pol)
		return pol;

	pol = XCALLOC(MTYPE_PRP_POLICY, sizeof(*pol));
	pol->name = XSTRDUP(MTYPE_PRP_POLICY, name);
	pol->peer_hash = hash_create(prp_peer_hash_key, prp_peer_hash_cmp,
				     "Peer RT policy peer hash");
	listnode_add(prp_policy_list, pol);
	return pol;
}

static void prp_policy_destroy(struct prp_policy *pol)
{
	listnode_delete(prp_policy_list, pol);
	hash_clean_and_free(&pol->peer_hash, prp_peer_entry_free);
	XFREE(MTYPE_PRP_POLICY, pol->name);
	XFREE(MTYPE_PRP_POLICY, pol);
}

static struct prp_peer_entry *prp_peer_lookup(struct prp_policy *pol,
					      const union sockunion *su)
{
	struct prp_peer_entry lookup;

	lookup.su = *su;
	return hash_lookup(pol->peer_hash, &lookup);
}

static struct prp_peer_entry *prp_peer_get(struct prp_policy *pol,
					   const union sockunion *su)
{
	struct prp_peer_entry lookup;

	lookup.su = *su;
	return hash_get(pol->peer_hash, &lookup, prp_peer_hash_alloc);
}

static void prp_peer_remove(struct prp_policy *pol,
			    struct prp_peer_entry *entry)
{
	hash_release(pol->peer_hash, entry);
	prp_peer_entry_free(entry);
}

/* ===================================================================
 * CLI: peer-rt-policy NAME peer A.B.C.D permit rt (1-16777215) ...
 * =================================================================== */

DEFUN(peer_rt_policy_permit,
      peer_rt_policy_permit_cmd,
      "peer-rt-policy WORD peer A.B.C.D permit rt (1-16777215)...",
      "Per-peer RT allow-list policy\n"
      "Policy name\n"
      "Specify a peer\n"
      "Peer IPv4 address\n"
      "Permit action\n"
      "Route Target assigned-value\n"
      "Assigned number (admin field is ignored)\n")
{
	const char *name = argv[1]->arg;
	const char *addr_str = argv[3]->arg;
	struct prp_policy *pol;
	struct prp_peer_entry *entry;
	union sockunion su;
	int i;

	if (str2sockunion(addr_str, &su) < 0) {
		vty_out(vty, "%% Invalid peer address: %s\n", addr_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	pol = prp_policy_get(name);
	entry = prp_peer_get(pol, &su);

	for (i = 6; i < argc; i++) {
		unsigned long val;
		char *endp;

		val = strtoul(argv[i]->arg, &endp, 10);
		if (*endp != '\0' || val == 0 || val > 16777215) {
			vty_out(vty, "%% Invalid assigned-value: %s\n",
				argv[i]->arg);
			continue;
		}
		prp_allowed_add(entry, (uint32_t)val);
	}

	return CMD_SUCCESS;
}

/* ===================================================================
 * CLI: no peer-rt-policy NAME [peer A.B.C.D [permit rt (1-16777215)...]]
 * =================================================================== */

/* "no peer-rt-policy NAME" — delete whole policy */
DEFUN(no_peer_rt_policy,
      no_peer_rt_policy_cmd,
      "no peer-rt-policy WORD",
      NO_STR
      "Per-peer RT allow-list policy\n"
      "Policy name\n")
{
	const char *name = argv[2]->arg;
	struct prp_policy *pol;

	pol = prp_policy_lookup(name);
	if (!pol) {
		vty_out(vty, "%% Policy '%s' not found\n", name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	prp_policy_destroy(pol);
	return CMD_SUCCESS;
}

/* "no peer-rt-policy NAME peer A.B.C.D" — delete whole peer */
DEFUN(no_peer_rt_policy_peer,
      no_peer_rt_policy_peer_cmd,
      "no peer-rt-policy WORD peer A.B.C.D",
      NO_STR
      "Per-peer RT allow-list policy\n"
      "Policy name\n"
      "Specify a peer\n"
      "Peer IPv4 address\n")
{
	const char *name = argv[2]->arg;
	struct prp_policy *pol;
	struct prp_peer_entry *entry;
	union sockunion su;

	pol = prp_policy_lookup(name);
	if (!pol) {
		vty_out(vty, "%% Policy '%s' not found\n", name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (str2sockunion(argv[4]->arg, &su) < 0) {
		vty_out(vty, "%% Invalid peer address: %s\n", argv[4]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	entry = prp_peer_lookup(pol, &su);
	if (!entry) {
		vty_out(vty, "%% No entry for peer %s in policy '%s'\n",
			argv[4]->arg, name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	prp_peer_remove(pol, entry);
	return CMD_SUCCESS;
}

/* "no peer-rt-policy NAME peer A.B.C.D permit rt VAL..." — remove specific values */
DEFUN(no_peer_rt_policy_rt,
      no_peer_rt_policy_rt_cmd,
      "no peer-rt-policy WORD peer A.B.C.D permit rt (1-16777215)...",
      NO_STR
      "Per-peer RT allow-list policy\n"
      "Policy name\n"
      "Specify a peer\n"
      "Peer IPv4 address\n"
      "Permit action\n"
      "Route Target assigned-value\n"
      "Assigned number (admin field is ignored)\n")
{
	const char *name = argv[2]->arg;
	struct prp_policy *pol;
	struct prp_peer_entry *entry;
	union sockunion su;
	int i;

	pol = prp_policy_lookup(name);
	if (!pol) {
		vty_out(vty, "%% Policy '%s' not found\n", name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (str2sockunion(argv[4]->arg, &su) < 0) {
		vty_out(vty, "%% Invalid peer address: %s\n", argv[4]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	entry = prp_peer_lookup(pol, &su);
	if (!entry) {
		vty_out(vty, "%% No entry for peer %s in policy '%s'\n",
			argv[4]->arg, name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	for (i = 7; i < argc; i++) {
		unsigned long val;
		char *endp;

		val = strtoul(argv[i]->arg, &endp, 10);
		if (*endp != '\0' || val == 0 || val > 16777215) {
			vty_out(vty, "%% Invalid assigned-value: %s\n",
				argv[i]->arg);
			continue;
		}
		prp_allowed_del(entry, (uint32_t)val);
	}

	if (entry->allowed_count == 0)
		prp_peer_remove(pol, entry);

	return CMD_SUCCESS;
}

/* ===================================================================
 * Show command
 * =================================================================== */

struct prp_show_ctx {
	struct vty *vty;
	const char *name;
};

static void prp_show_peer_iter(struct hash_bucket *hb, void *arg)
{
	struct prp_peer_entry *entry = hb->data;
	struct prp_show_ctx *ctx = arg;
	size_t i;

	if (entry->allowed_count == 0) {
		vty_out(ctx->vty, "  peer %pSU (no RTs)\n", &entry->su);
		return;
	}

	vty_out(ctx->vty, "  peer %pSU permit rt", &entry->su);
	for (i = 0; i < entry->allowed_count; i++)
		vty_out(ctx->vty, " %u", entry->allowed[i]);
	vty_out(ctx->vty, "\n");
}

DEFPY(show_peer_rt_policy,
      show_peer_rt_policy_cmd,
      "show peer-rt-policy [WORD$name]",
      SHOW_STR
      "Per-peer RT allow-list policy\n"
      "Policy name (show all if omitted)\n")
{
	struct listnode *node;
	struct prp_policy *pol;

	if (!prp_policy_list || list_isempty(prp_policy_list)) {
		vty_out(vty, "No peer-rt-policies defined\n");
		return CMD_SUCCESS;
	}

	for (ALL_LIST_ELEMENTS_RO(prp_policy_list, node, pol)) {
		struct prp_show_ctx ctx = { .vty = vty, .name = pol->name };

		if (name && strcmp(pol->name, name) != 0)
			continue;

		vty_out(vty, "peer-rt-policy %s (%u peers)\n",
			pol->name, pol->peer_hash->count);
		hash_iterate(pol->peer_hash, prp_show_peer_iter, &ctx);
	}

	return CMD_SUCCESS;
}

/* ===================================================================
 * Route-map match: "match peer-rt-policy NAME"
 * =================================================================== */

static void prp_schedule_reset(struct prp_peer_entry *entry,
			       struct peer *peer)
{
	union sockunion *su_copy;

	if (event_is_scheduled(entry->t_reset))
		return;

	su_copy = XCALLOC(MTYPE_PRP_ENTRY, sizeof(*su_copy));
	*su_copy = entry->su;

	event_add_event(bm->master, prp_peer_reset_event, su_copy, 0,
			&entry->t_reset);
}

struct prp_match_rule {
	char *name;
	bool reset_on_violation;
};

static enum route_map_cmd_result_t
route_match_peer_rt_policy(void *rule, const struct prefix *prefix,
			   void *object)
{
	struct prp_match_rule *mr = rule;
	struct bgp_path_info *path = object;
	struct peer *peer;
	struct prp_policy *pol;
	struct prp_peer_entry *entry;
	struct ecommunity *ecom;
	uint32_t i;
	bool has_rt = false;

	if (!path || !path->peer || !path->attr)
		return RMAP_NOMATCH;

	peer = path->peer;
	pol = prp_policy_lookup(mr->name);
	if (!pol)
		return RMAP_NOMATCH;

	entry = prp_peer_lookup(pol, &peer->connection->su);
	if (!entry)
		return RMAP_NOMATCH;

	ecom = bgp_attr_get_ecommunity(path->attr);
	if (!ecom || ecom->size == 0)
		return RMAP_MATCH;

	for (i = 0; i < ecom->size; i++) {
		uint8_t *pnt = ecom->val + (i * ecom->unit_size);
		uint8_t type = pnt[0] & ~ECOMMUNITY_FLAG_NON_TRANSITIVE;
		uint8_t sub_type = pnt[1];
		uint32_t assigned;

		if (sub_type != ECOMMUNITY_ROUTE_TARGET)
			continue;

		if (type != ECOMMUNITY_ENCODE_AS &&
		    type != ECOMMUNITY_ENCODE_IP &&
		    type != ECOMMUNITY_ENCODE_AS4)
			continue;

		has_rt = true;

		assigned = prp_rt_assigned_value(pnt);
		if (!prp_allowed_contains(entry, assigned)) {
			if (mr->reset_on_violation)
				prp_schedule_reset(entry, peer);
			return RMAP_NOMATCH;
		}
	}

	if (!has_rt)
		return RMAP_MATCH;

	return RMAP_MATCH;
}

static void *route_match_peer_rt_policy_compile(const char *arg)
{
	struct prp_match_rule *mr;
	char name_buf[256];
	bool reset = false;

	if (sscanf(arg, "%255s", name_buf) != 1)
		return NULL;

	if (strstr(arg, "reset-on-violation"))
		reset = true;

	mr = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(*mr));
	mr->name = XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, name_buf);
	mr->reset_on_violation = reset;
	return mr;
}

static void route_match_peer_rt_policy_free(void *rule)
{
	struct prp_match_rule *mr = rule;

	XFREE(MTYPE_ROUTE_MAP_COMPILED, mr->name);
	XFREE(MTYPE_ROUTE_MAP_COMPILED, mr);
}

static const struct route_map_rule_cmd route_match_peer_rt_policy_cmd_rule = {
	"peer-rt-policy",
	route_match_peer_rt_policy,
	route_match_peer_rt_policy_compile,
	route_match_peer_rt_policy_free
};

DEFUN(match_peer_rt_policy,
      match_peer_rt_policy_cmd,
      "match peer-rt-policy WORD [reset-on-violation]",
      MATCH_STR
      "Match against per-peer RT allow-list\n"
      "Policy name\n"
      "Reset peer on unauthorized RT (use for inbound only)\n")
{
	VTY_DECLVAR_CONTEXT(route_map_index, index);
	const char *name = argv[2]->arg;
	char rule_arg[300];

	if (argc > 3)
		snprintf(rule_arg, sizeof(rule_arg), "%s reset-on-violation",
			 name);
	else
		snprintf(rule_arg, sizeof(rule_arg), "%s", name);

	return route_map_add_match(index, "peer-rt-policy", rule_arg,
				   RMAP_EVENT_MATCH_ADDED);
}

DEFUN(no_match_peer_rt_policy,
      no_match_peer_rt_policy_cmd,
      "no match peer-rt-policy [WORD [reset-on-violation]]",
      NO_STR
      MATCH_STR
      "Match against per-peer RT allow-list\n"
      "Policy name\n"
      "Reset peer on unauthorized RT\n")
{
	VTY_DECLVAR_CONTEXT(route_map_index, index);
	const char *name = (argc > 3) ? argv[3]->arg : NULL;
	char rule_arg[300];

	if (name) {
		if (argc > 4)
			snprintf(rule_arg, sizeof(rule_arg),
				 "%s reset-on-violation", name);
		else
			snprintf(rule_arg, sizeof(rule_arg), "%s", name);
		return route_map_delete_match(index, "peer-rt-policy",
					      rule_arg,
					      RMAP_EVENT_MATCH_DELETED);
	}

	return route_map_delete_match(index, "peer-rt-policy", NULL,
				      RMAP_EVENT_MATCH_DELETED);
}

/* ===================================================================
 * Config write — persist policies on "write mem"
 * =================================================================== */

static void prp_config_write_peer(struct hash_bucket *hb, void *arg)
{
	struct prp_peer_entry *entry = hb->data;
	struct prp_show_ctx *ctx = arg;
	size_t i;

	if (entry->allowed_count == 0)
		return;

	vty_out(ctx->vty, "peer-rt-policy %s peer %pSU permit rt",
		ctx->name, &entry->su);
	for (i = 0; i < entry->allowed_count; i++)
		vty_out(ctx->vty, " %u", entry->allowed[i]);
	vty_out(ctx->vty, "\n");
}

static int prp_config_write(struct vty *vty)
{
	struct listnode *node;
	struct prp_policy *pol;

	if (!prp_policy_list)
		return 0;

	for (ALL_LIST_ELEMENTS_RO(prp_policy_list, node, pol)) {
		struct prp_show_ctx ctx = { .vty = vty, .name = pol->name };

		hash_iterate(pol->peer_hash, prp_config_write_peer, &ctx);
	}

	return 0;
}

static int prp_config_write_debug(struct vty *vty, bool running)
{
	if (running)
		return prp_config_write(vty);
	return 0;
}

/* ===================================================================
 * Module init
 * =================================================================== */

void bgp_peer_rt_policy_init(void)
{
	prp_policy_list = list_new();

	install_element(CONFIG_NODE, &peer_rt_policy_permit_cmd);
	install_element(CONFIG_NODE, &no_peer_rt_policy_cmd);
	install_element(CONFIG_NODE, &no_peer_rt_policy_peer_cmd);
	install_element(CONFIG_NODE, &no_peer_rt_policy_rt_cmd);

	install_element(VIEW_NODE, &show_peer_rt_policy_cmd);

	route_map_install_match(&route_match_peer_rt_policy_cmd_rule);
	install_element(RMAP_NODE, &match_peer_rt_policy_cmd);
	install_element(RMAP_NODE, &no_match_peer_rt_policy_cmd);

	hook_register(bgp_hook_config_write_debug, prp_config_write_debug);

	zlog_info("PEER-RT-POLICY: initialized");
}
