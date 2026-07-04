// SPDX-License-Identifier: GPL-2.0-or-later
/* Dynamic BGP EVPN Type-5 Aggregation Module
 *
 * Runs on a BGP Route Reflector (RR). Three independent features:
 *
 * Example configuration:
 *   dynamic-aggr
 *    site-id 222
 *    community-asn 65000
 *    rd-id-base 50000
 *    grid GRID-A rt 100:501
 *    grid GRID-B rt 100:502
 *    grid GRID-C rt 100:503
 *    grid GRID-D rt 100:504
 *    static-aggregate prefix 192.168.1.0/24 grid GRID-B vni 60
 *    dynamic-aggregate prefix 10.10.0.0/22 slice-prefixlen 26
 *    dynamic-aggregate prefix 10.20.0.0/22 slice-prefixlen 26
 *    dynamic-aggregate global community 60:60
 *   !
 *
 * Static Aggregation:
 *   Pre-defined (prefix, grid, VNI) tuples originated once EVPN is
 *   ready. These are aggregates already defined per grid. The module
 *   originates these Type-5 routes and keeps them
 *   present. Static aggregation is not driven by route updates and is
 *   not withdrawn by announce/withdraw processing.
 *
 * Scoped Dynamic Aggregation:
 *   Observes EVPN Type-5 routes arriving in the loc-rib. Configured
 *   supernets here are not pinned to a specific grid. Think of each
 *   supernet as a shared Kubernetes IP pool: when a node needs a slice
 *   (for example /26), the pool allocates one, and that node may belong
 *   to any grid. Grid (community) and VNI (label) are therefore inferred
 *   from incoming routes, then tracked with per-(grid, VNI) slot
 *   occupancy. The module detects contiguous aligned blocks and
 *   originates/withdraws aggregate Type-5 routes. This path is scoped by
 *   prefix only. Contributing routes covered by an active aggregate are
 *   suppressed.
 *
 * Global Dynamic Aggregation:
 *   Optional fallback for routes that do not match any configured scoped
 *   dynamic aggregate supernet. In this mode, a supernet boundary is
 *   not known/configured. Routes are first filtered by explicit match
 *   rules (currently standard community only). From each route we learn
 *   grid, VNI, and prefix length, then group prefixes with the same
 *   criteria and aggregate them dynamically in Patricia tries keyed by
 *   (match-rule, grid, VNI, prefixlen).
 *
 * All three features stamp a grid community on aggregates. The route-target
 * is also stamped in code as site-id:VNI. Other attributes (next-hop,
 * RMAC) are expected to be set by the outbound route-map
 * which matches on that community.
 *
 */

#include <zebra.h> /* FRR base: stdint, stdbool, netinet, etc. */

#include "command.h" /* DEFUN macro, install_element, CMD_SUCCESS */
#include "prefix.h"  /* struct prefix, prefix_match, apply_mask */
#include "memory.h"  /* XCALLOC, XFREE, XREALLOC, DEFINE_MTYPE */
#include "log.h"     /* zlog_info, zlog_err, zlog_warn */
#include "table.h"   /* route_table operations */
#include "vty.h"     /* vty_out, struct vty (show command) */
#include "mpls.h"    /* vni2label, label2vni, vni_t */

#include "bgpd/bgpd.h"	    /* struct bgp, bgp_get_evpn, peer_self, linklist.h */
#include "bgpd/bgp_table.h" /* bgp_dest_get_prefix, bgp_node_get */
#include "bgpd/bgp_route.h" /* route update hook, path info helpers */
#include "bgpd/bgp_attr.h"	/* bgp_attr_default_set, bgp_attr_intern, bgp_attr_set_community */
#include "bgpd/bgp_aspath.h"	/* aspath_unintern */
#include "bgpd/bgp_community.h" /* community_str2com, community_val_get, bgp_attr_get_community */
#include "bgpd/bgp_ecommunity.h"   /* ecommunity_dup, bgp_attr_set_ecommunity */
#include "bgpd/bgp_memory.h"	   /* MTYPE_BGP_* memory types */
#include "bgpd/bgp_evpn.h"	   /* bgp_evpn_path_info_get_l3vni, bgp_evpn_path_info_extra_get */
#include "bgpd/bgp_evpn_private.h" /* EVPN Type-5 helpers and lookup */
#include "bgpd/bgp_rd.h"	   /* form_auto_rd, struct prefix_rd */
#include "bgpd/bgp_encap_types.h"  /* encode_encap_extcomm, BGP_ENCAP_TYPE_VXLAN */
#include "bgpd/bgp_label.h"	   /* bgp_labels_intern, bgp_labels_unintern */
#include "bgpd/bgp_attr_evpn.h"    /* bgp_attr_rmac */

DEFINE_MGROUP(DYNAGGR, "Dynamic Aggregation");
DEFINE_MTYPE_STATIC(DYNAGGR, DYNAGGR, "Dynamic aggr data");

/*
 * Sentinel address used as our suppressor identity in the
 * bgp_path_info_extra->aggr_suppressors list (scoped and global dynamic
 * aggregation only; static aggregation does not use suppression).
 */
static int dynaggr_suppressor_tag;

/* ===================================================================
 * Runtime Data Structures
 * =================================================================== */

struct grid {
	char *name;
	uint16_t community_val;
	char *rt;
	uint16_t rd_id;
};

/* Static Aggregation: parsed static aggregate (originated when EVPN is ready, permanent) */
struct static_aggregate {
	struct prefix prefix;
	struct grid *grid;
	char *grid_name;
	vni_t vni;
};

/* Dynamic Aggregation: per-(grid, VNI) bucket under an scoped supernet */
struct scoped_dynaggr_bucket {
	struct grid *grid;
	vni_t vni;
	uint32_t num_slices;
	uint32_t total_slots;
	struct bgp_path_info **slot_paths;

	struct prefix *active_aggregates;
	uint32_t num_active_aggregates;

	struct scoped_dynaggr_bucket *next;
};

/* Dynamic Aggregation: scoped supernet */
struct scoped_dynaggr_supernet {
	struct prefix prefix;
	uint8_t slice_prefixlen;
	uint32_t total_slots;
	struct scoped_dynaggr_bucket *grid_buckets;
};

struct global_dynaggr_rule {
	uint32_t match_community;
	char *community_str;
	struct global_dynaggr_rule *next;
};

struct global_dynaggr_tnode {
	struct bgp_path_info *path;
	bool is_aggregate;
	uint32_t skip_bits;
	uint8_t num_skipped;
	struct global_dynaggr_tnode *child[2];
};

struct global_dynaggr_slice_bucket {
	uint8_t slice_prefixlen;
	struct global_dynaggr_tnode *tree_root;
	uint32_t tree_leaf_count;
	uint32_t num_active_aggregates;
	struct global_dynaggr_slice_bucket *next;
};

struct global_dynaggr_bucket {
	const struct global_dynaggr_rule *rule;
	struct grid *grid;
	vni_t vni;
	struct global_dynaggr_slice_bucket *tree_slices;
	struct global_dynaggr_bucket *next;
};

/* Dynamic Nexthop: one T2 identity entry */
struct dynaggr_nexthop_entry {
	char peer_host[INET6_ADDRSTRLEN + 1]; /* peer IP string (unique key) */
	struct in_addr vtep_ip;               /* EVPN next-hop = VTEP */
	struct ethaddr rmac;                  /* Router MAC from extended community */
	vni_t vni;
	struct dynaggr_nexthop_entry *next;
};

/* Dynamic Nexthop: per-grid list of discovered T2 entries */
struct dynaggr_nexthop_grid {
	struct grid *grid;
	struct dynaggr_nexthop_entry *entries;
	uint32_t count;
	struct dynaggr_nexthop_grid *next;
};

struct dynaggr_config {
	uint16_t site_id;
	uint16_t community_asn;
	uint16_t rd_id_base;
	bool has_site_id;
	bool has_community_asn;
	bool has_rd_id_base;
	bool enabled;
};

static struct grid *grids;
static uint32_t num_grids;

static struct static_aggregate *static_aggregates;
static uint32_t num_static_aggregates;
static bool static_aggregates_originated;

static struct scoped_dynaggr_supernet *scoped_dynaggr_supernets;
static uint32_t num_scoped_dynaggr_supernets;
static struct global_dynaggr_rule *global_dynaggr_rules;
static uint32_t num_global_dynaggr_rules;
static struct global_dynaggr_bucket *global_dynaggr_buckets;
static bool dynaggr_cli_installed;

/* Dynamic nexthop anchor config and registry */
static bool dynaggr_nexthop_anchor_set;
static struct prefix dynaggr_nexthop_anchor;
static struct dynaggr_nexthop_grid *dynaggr_nexthop_grids;

static struct dynaggr_config dynaggr_cfg = {
	.enabled = false,
};

static uint16_t rd_id_next;

static int dynaggr_config_write(struct vty *vty);
static void inject_aggregate(struct bgp *bgp, const struct prefix *aggr_pfx, struct grid *grid,
			     vni_t vni);
static void remove_aggregate(struct bgp *bgp, const struct prefix *aggr_pfx, struct grid *grid,
			     vni_t vni);

static struct cmd_node dynaggr_node = {
	.name = "dynamic-aggr",
	.node = DYNAGGR_NODE,
	.parent_node = CONFIG_NODE,
	.config_write = dynaggr_config_write,
	.prompt = "%s(config-dynamic-aggr)# ",
};

/* ===================================================================
 * Helpers
 * =================================================================== */

/*
 * Find a configured grid by its local community value.
 */
static struct grid *find_grid_by_community(uint16_t val)
{
	uint32_t i;
	for (i = 0; i < num_grids; i++) {
		if (grids[i].community_val == val)
			return &grids[i];
	}
	return NULL;
}

/*
 * Find a configured grid by its CLI name.
 */
static struct grid *find_grid_by_name(const char *name)
{
	uint32_t i;
	for (i = 0; i < num_grids; i++) {
		if (strcmp(grids[i].name, name) == 0)
			return &grids[i];
	}
	return NULL;
}

/*
 * Check whether a route carries a specific standard community value.
 */
static bool route_has_community_value(struct bgp_path_info *route, uint32_t match_community)
{
	struct community *comm;
	int i;

	if (!route || !route->attr)
		return false;

	comm = bgp_attr_get_community(route->attr);
	if (!comm)
		return false;

	for (i = 0; i < (int)comm->size; i++) {
		if (community_val_get(comm, i) == match_community)
			return true;
	}

	return false;
}

/*
 * Return the first configured global dynamic aggregation rule matching a route.
 */
static const struct global_dynaggr_rule *match_global_dynaggr_rule(struct bgp_path_info *route)
{
	struct global_dynaggr_rule *rule;

	for (rule = global_dynaggr_rules; rule; rule = rule->next) {
		if (route_has_community_value(route, rule->match_community))
			return rule;
	}

	return NULL;
}

/*
 * Infer the configured grid from a route's grid community.
 */
static struct grid *get_grid_from_route(struct bgp_path_info *route)
{
	struct community *comm;
	int i;
	uint32_t val;
	uint16_t asn, grid_val;

	if (!dynaggr_cfg.has_community_asn)
		return NULL;

	if (!route || !route->attr)
		return NULL;

	comm = bgp_attr_get_community(route->attr);
	if (!comm)
		return NULL;

	for (i = 0; i < (int)comm->size; i++) {
		val = community_val_get(comm, i);
		asn = (val >> 16) & 0xFFFF;
		grid_val = val & 0xFFFF;

		if (asn == dynaggr_cfg.community_asn && grid_val != 0)
			return find_grid_by_community(grid_val);
	}

	return NULL;
}

/*
 * Infer the L3VNI from an EVPN Type-5 route.
 */
static vni_t get_vni_from_route(struct bgp_path_info *route)
{
	return bgp_evpn_path_info_get_l3vni(route);
}

/*
 * Convert a scoped dynamic route prefix into its slot within a supernet.
 */
static uint32_t scoped_dynaggr_prefix_to_slot(const struct prefix *p,
					      const struct scoped_dynaggr_supernet *scoped)
{
	uint32_t p_addr = ntohl(p->u.prefix4.s_addr);
	uint32_t s_addr = ntohl(scoped->prefix.u.prefix4.s_addr);
	uint32_t slot_size = 1 << (32 - scoped->slice_prefixlen);

	return (p_addr - s_addr) / slot_size;
}

/*
 * Find or create the scoped dynamic bucket for a supernet, grid, and VNI.
 */
static struct scoped_dynaggr_bucket *
scoped_dynaggr_get_bucket(struct scoped_dynaggr_supernet *scoped, struct grid *grid, vni_t vni)
{
	struct scoped_dynaggr_bucket *b;

	for (b = scoped->grid_buckets; b; b = b->next) {
		if (b->grid == grid && b->vni == vni)
			return b;
	}

	b = XCALLOC(MTYPE_DYNAGGR, sizeof(*b));
	b->grid = grid;
	b->vni = vni;
	b->total_slots = scoped->total_slots;
	b->slot_paths = XCALLOC(MTYPE_DYNAGGR, b->total_slots * sizeof(struct bgp_path_info *));
	b->num_slices = 0;
	b->active_aggregates = NULL;
	b->num_active_aggregates = 0;
	b->next = scoped->grid_buckets;
	scoped->grid_buckets = b;

	return b;
}

/*
 * Find or create the global dynamic bucket for a rule, grid, and VNI.
 */
static struct global_dynaggr_bucket *
global_dynaggr_get_bucket(const struct global_dynaggr_rule *rule, struct grid *grid, vni_t vni)
{
	struct global_dynaggr_bucket *b;

	for (b = global_dynaggr_buckets; b; b = b->next) {
		if (b->rule == rule && b->grid == grid && b->vni == vni)
			return b;
	}

	b = XCALLOC(MTYPE_DYNAGGR, sizeof(*b));
	b->rule = rule;
	b->grid = grid;
	b->vni = vni;
	b->next = global_dynaggr_buckets;
	global_dynaggr_buckets = b;

	return b;
}

/*
 * Find or create the global dynamic Patricia tree for one learned prefix length.
 */
static struct global_dynaggr_slice_bucket *
global_dynaggr_get_or_create_slice(struct global_dynaggr_bucket *bucket, uint8_t pfxlen)
{
	struct global_dynaggr_slice_bucket *s;

	for (s = bucket->tree_slices; s; s = s->next) {
		if (s->slice_prefixlen == pfxlen)
			return s;
	}

	s = XCALLOC(MTYPE_DYNAGGR, sizeof(*s));
	s->slice_prefixlen = pfxlen;
	s->next = bucket->tree_slices;
	bucket->tree_slices = s;
	return s;
}

/* ===================================================================
 * Suppression (Scoped + Global Dynamic Aggregation)
 *
 * Uses FRR's built-in aggr_suppressors list on bgp_path_info_extra.
 * &dynaggr_suppressor_tag is our unique suppressor identity.
 * =================================================================== */

/*
 * Mark a contributing path as suppressed by this module.
 */
static void suppress_path(struct bgp *bgp_evpn, struct bgp_path_info *pi)
{
	struct bgp_path_info_extra *pie;

	if (!pi)
		return;

	pie = bgp_path_info_extra_get(pi);

	if (pie->aggr_suppressors == NULL)
		pie->aggr_suppressors = list_new();

	if (listnode_lookup(pie->aggr_suppressors, &dynaggr_suppressor_tag))
		return;

	listnode_add(pie->aggr_suppressors, &dynaggr_suppressor_tag);

	if (listcount(pie->aggr_suppressors) == 1) {
		bgp_path_info_set_flag(pi->net, pi, BGP_PATH_ATTR_CHANGED);
		bgp_process(bgp_evpn, pi->net, pi, AFI_L2VPN, SAFI_EVPN);
	}
}

/*
 * Remove this module's suppression marker from a contributing path.
 */
static void unsuppress_path(struct bgp *bgp_evpn, struct bgp_path_info *pi)
{
	if (!pi || !pi->extra || !pi->extra->aggr_suppressors)
		return;

	if (!listnode_lookup(pi->extra->aggr_suppressors, &dynaggr_suppressor_tag))
		return;

	listnode_delete(pi->extra->aggr_suppressors, &dynaggr_suppressor_tag);

	if (listcount(pi->extra->aggr_suppressors) == 0) {
		list_delete(&pi->extra->aggr_suppressors);
		/*
		 * During daemon shutdown, EVPN context can already be gone while
		 * dynamic-aggr runtime is being torn down via frr_fini.
		 */
		if (!bgp_evpn)
			return;
		bgp_path_info_set_flag(pi->net, pi, BGP_PATH_ATTR_CHANGED);
		bgp_process(bgp_evpn, pi->net, pi, AFI_L2VPN, SAFI_EVPN);
	}
}

/*
 * Build an IPv4 prefix from a host-byte-order address and prefix length.
 */
static struct prefix make_prefix_hbo(uint32_t addr_host, uint8_t pfxlen)
{
	struct prefix p;

	memset(&p, 0, sizeof(p));
	p.family = AF_INET;
	p.u.prefix4.s_addr = htonl(addr_host);
	p.prefixlen = pfxlen;
	return p;
}

/*
 * Check whether a Patricia node has exactly one child and return its bit.
 */
static bool global_dynaggr_tnode_single_child(const struct global_dynaggr_tnode *n, int *bit)
{
	if (!n)
		return false;
	if (n->child[0] && !n->child[1]) {
		*bit = 0;
		return true;
	}
	if (!n->child[0] && n->child[1]) {
		*bit = 1;
		return true;
	}
	return false;
}

/*
 * Recompute compressed skip bits for a Patricia subtree.
 */
static void global_dynaggr_tnode_rebuild_patricia(struct global_dynaggr_tnode *n)
{
	struct global_dynaggr_tnode *cur;
	uint32_t bits = 0;
	uint8_t count = 0;
	int bit = 0;

	if (!n)
		return;

	global_dynaggr_tnode_rebuild_patricia(n->child[0]);
	global_dynaggr_tnode_rebuild_patricia(n->child[1]);

	n->skip_bits = 0;
	n->num_skipped = 0;

	if (n->path || n->is_aggregate)
		return;

	cur = n;
	while (count < 31 && global_dynaggr_tnode_single_child(cur, &bit) && !cur->path &&
	       !cur->is_aggregate) {
		bits = (bits << 1) | (uint32_t)bit;
		count++;
		cur = cur->child[bit];
		if (!cur)
			break;
		if (cur->path || cur->is_aggregate)
			break;
	}

	n->skip_bits = bits;
	n->num_skipped = count;
}

/*
 * Find or create the Patricia node for an address and prefix length.
 */
static struct global_dynaggr_tnode *global_dynaggr_tnode_get(struct global_dynaggr_tnode **root_ptr,
							     uint32_t addr, uint8_t pfxlen)
{
	struct global_dynaggr_tnode *n;
	int d;

	if (!*root_ptr)
		*root_ptr = XCALLOC(MTYPE_DYNAGGR, sizeof(struct global_dynaggr_tnode));
	n = *root_ptr;
	for (d = 0; d < pfxlen; d++) {
		int bit = (addr >> (31 - d)) & 1;

		if (!n->child[bit])
			n->child[bit] = XCALLOC(MTYPE_DYNAGGR, sizeof(struct global_dynaggr_tnode));
		n = n->child[bit];
	}
	return n;
}

/*
 * Find the Patricia node for an address and prefix length.
 */
static struct global_dynaggr_tnode *global_dynaggr_tnode_find(struct global_dynaggr_tnode *root,
							      uint32_t addr, uint8_t pfxlen)
{
	struct global_dynaggr_tnode *n = root;
	int d;

	for (d = 0; d < pfxlen && n; d++) {
		int bit = (addr >> (31 - d)) & 1;

		n = n->child[bit];
	}
	return n;
}

/*
 * Check whether a subtree can be represented by a real path or aggregate.
 */
static bool global_dynaggr_tnode_representable(struct global_dynaggr_tnode *n)
{
	if (!n)
		return false;
	if (n->path || n->is_aggregate)
		return true;
	return global_dynaggr_tnode_representable(n->child[0]) &&
	       global_dynaggr_tnode_representable(n->child[1]);
}

/*
 * Free a Patricia subtree.
 */
static void global_dynaggr_tnode_free(struct global_dynaggr_tnode *n)
{
	if (!n)
		return;
	global_dynaggr_tnode_free(n->child[0]);
	global_dynaggr_tnode_free(n->child[1]);
	XFREE(MTYPE_DYNAGGR, n);
}

static void global_dynaggr_tnode_clear_runtime(struct bgp *bgp_evpn, struct global_dynaggr_tnode *n,
					       uint32_t addr, uint8_t depth,
					       struct global_dynaggr_slice_bucket *sb,
					       struct global_dynaggr_bucket *bucket)
{
	if (!n)
		return;

	if (n->is_aggregate) {
		struct prefix p = make_prefix_hbo(addr, depth);

		remove_aggregate(NULL, &p, bucket->grid, bucket->vni);
		if (sb->num_active_aggregates > 0)
			sb->num_active_aggregates--;
		n->is_aggregate = false;
	}

	if (bgp_evpn && n->path)
		unsuppress_path(bgp_evpn, n->path);

	global_dynaggr_tnode_clear_runtime(bgp_evpn, n->child[0], addr, depth + 1, sb, bucket);
	global_dynaggr_tnode_clear_runtime(bgp_evpn, n->child[1],
					   addr | (depth < 32 ? (1u << (31 - depth)) : 0),
					   depth + 1, sb, bucket);
}

/*
 * Suppress all contributing route leaves below a Patricia node.
 */
static void global_dynaggr_tnode_suppress_leaves(struct bgp *bgp_evpn,
						 struct global_dynaggr_tnode *n)
{
	if (!n)
		return;
	if (n->is_aggregate)
		return;
	if (n->path)
		suppress_path(bgp_evpn, n->path);
	global_dynaggr_tnode_suppress_leaves(bgp_evpn, n->child[0]);
	global_dynaggr_tnode_suppress_leaves(bgp_evpn, n->child[1]);
}

/*
 * Unsuppress all contributing route leaves below a Patricia node.
 */
static void global_dynaggr_tnode_unsuppress_leaves(struct bgp *bgp_evpn,
						   struct global_dynaggr_tnode *n)
{
	if (!n)
		return;
	if (n->is_aggregate)
		return;
	if (n->path)
		unsuppress_path(bgp_evpn, n->path);
	global_dynaggr_tnode_unsuppress_leaves(bgp_evpn, n->child[0]);
	global_dynaggr_tnode_unsuppress_leaves(bgp_evpn, n->child[1]);
}

/*
 * Withdraw aggregate nodes below a Patricia subtree.
 */
static void global_dynaggr_tnode_withdraw_aggregates(struct global_dynaggr_tnode *n, uint32_t addr,
						     uint8_t depth,
						     struct global_dynaggr_slice_bucket *sb,
						     struct global_dynaggr_bucket *bucket)
{
	if (!n)
		return;
	if (n->is_aggregate) {
		struct prefix p = make_prefix_hbo(addr, depth);

		remove_aggregate(NULL, &p, bucket->grid, bucket->vni);
		if (sb->num_active_aggregates > 0)
			sb->num_active_aggregates--;
		n->is_aggregate = false;
		return;
	}

	global_dynaggr_tnode_withdraw_aggregates(n->child[0], addr, depth + 1, sb, bucket);
	global_dynaggr_tnode_withdraw_aggregates(n->child[1],
						 addr | (depth < 32 ? (1u << (31 - depth)) : 0),
						 depth + 1, sb, bucket);
}

/*
 * Re-evaluate a Patricia subtree after an aggregate is withdrawn.
 */
static void global_dynaggr_tnode_re_evaluate(struct bgp *bgp_evpn, struct global_dynaggr_tnode *n,
					     uint32_t addr, uint8_t depth,
					     struct global_dynaggr_slice_bucket *sb,
					     struct global_dynaggr_bucket *bucket)
{
	struct global_dynaggr_tnode *left;
	struct global_dynaggr_tnode *right;
	uint32_t raddr;

	if (!n)
		return;

	raddr = addr | (depth < 32 ? (1u << (31 - depth)) : 0);
	left = n->child[0];
	right = n->child[1];

	if (global_dynaggr_tnode_representable(left) && global_dynaggr_tnode_representable(right)) {
		if (!n->is_aggregate) {
			struct prefix p = make_prefix_hbo(addr, depth);

			inject_aggregate(NULL, &p, bucket->grid, bucket->vni);
			sb->num_active_aggregates++;
			n->is_aggregate = true;
		}

		global_dynaggr_tnode_withdraw_aggregates(left, addr, depth + 1, sb, bucket);
		global_dynaggr_tnode_withdraw_aggregates(right, raddr, depth + 1, sb, bucket);
		global_dynaggr_tnode_suppress_leaves(bgp_evpn, left);
		global_dynaggr_tnode_suppress_leaves(bgp_evpn, right);
	} else {
		global_dynaggr_tnode_re_evaluate(bgp_evpn, left, addr, depth + 1, sb, bucket);
		global_dynaggr_tnode_re_evaluate(bgp_evpn, right, raddr, depth + 1, sb, bucket);
	}
}

/*
 * Add an announced route to a global dynamic Patricia tree and aggregate it.
 */
static void global_dynaggr_tree_announce(struct bgp *bgp_evpn,
					 struct global_dynaggr_slice_bucket *sb,
					 struct global_dynaggr_bucket *bucket,
					 const struct prefix *pfx, struct bgp_path_info *path)
{
	struct global_dynaggr_tnode *leaf;
	uint32_t addr = ntohl(pfx->u.prefix4.s_addr);
	uint8_t pfxlen = pfx->prefixlen;
	uint32_t cur_addr;
	uint8_t cur_pfxlen;
	uint32_t best_addr = 0;
	uint8_t best_pfxlen = 0;
	bool found_agg = false;

	leaf = global_dynaggr_tnode_get(&sb->tree_root, addr, pfxlen);
	if (!leaf->path)
		sb->tree_leaf_count++;
	leaf->path = path;
	global_dynaggr_tnode_rebuild_patricia(sb->tree_root);

	cur_addr = addr;
	cur_pfxlen = pfxlen;
	while (cur_pfxlen > 0) {
		uint8_t parent_pfxlen = cur_pfxlen - 1;
		uint32_t parent_mask = parent_pfxlen ? (0xFFFFFFFFu << (32 - parent_pfxlen)) : 0;
		uint32_t parent_addr = cur_addr & parent_mask;
		uint32_t sibling_bit = 1u << (32 - cur_pfxlen);
		uint32_t sibling_addr = cur_addr ^ sibling_bit;
		struct global_dynaggr_tnode *sibling =
			global_dynaggr_tnode_find(sb->tree_root, sibling_addr, cur_pfxlen);

		if (!global_dynaggr_tnode_representable(sibling))
			break;

		best_addr = parent_addr;
		best_pfxlen = parent_pfxlen;
		found_agg = true;
		cur_addr = parent_addr;
		cur_pfxlen = parent_pfxlen;
	}

	if (found_agg) {
		struct global_dynaggr_tnode *agg_node =
			global_dynaggr_tnode_get(&sb->tree_root, best_addr, best_pfxlen);
		uint32_t raddr = best_addr | (best_pfxlen < 32 ? (1u << (31 - best_pfxlen)) : 0);

		if (!agg_node->is_aggregate) {
			struct prefix agg_pfx = make_prefix_hbo(best_addr, best_pfxlen);

			inject_aggregate(NULL, &agg_pfx, bucket->grid, bucket->vni);
			sb->num_active_aggregates++;
			agg_node->is_aggregate = true;
		}

		global_dynaggr_tnode_withdraw_aggregates(agg_node->child[0], best_addr,
							 best_pfxlen + 1, sb, bucket);
		global_dynaggr_tnode_withdraw_aggregates(agg_node->child[1], raddr,
							 best_pfxlen + 1, sb, bucket);
		global_dynaggr_tnode_suppress_leaves(bgp_evpn, agg_node->child[0]);
		global_dynaggr_tnode_suppress_leaves(bgp_evpn, agg_node->child[1]);
	} else {
		struct global_dynaggr_tnode *n = sb->tree_root;
		bool under_agg = false;
		int d;

		for (d = 0; d < pfxlen && n; d++) {
			if (n->is_aggregate) {
				under_agg = true;
				break;
			}
			n = n->child[(addr >> (31 - d)) & 1];
		}

		if (under_agg)
			suppress_path(bgp_evpn, path);
	}
}

/*
 * Remove a withdrawn route from a global dynamic Patricia tree and reconcile it.
 */
static void global_dynaggr_tree_withdraw(struct bgp *bgp_evpn,
					 struct global_dynaggr_slice_bucket *sb,
					 struct global_dynaggr_bucket *bucket,
					 const struct prefix *pfx, struct bgp_path_info *path)
{
	struct global_dynaggr_tnode *leaf;
	struct global_dynaggr_tnode *agg_node = NULL;
	struct global_dynaggr_tnode *n;
	uint32_t addr = ntohl(pfx->u.prefix4.s_addr);
	uint8_t pfxlen = pfx->prefixlen;
	uint32_t agg_addr = 0;
	uint8_t agg_pfxlen = 0;
	uint32_t walk_addr = 0;
	int d;

	leaf = global_dynaggr_tnode_find(sb->tree_root, addr, pfxlen);
	if (!leaf || leaf->path != path)
		return;

	leaf->path = NULL;
	if (sb->tree_leaf_count > 0)
		sb->tree_leaf_count--;
	global_dynaggr_tnode_rebuild_patricia(sb->tree_root);

	n = sb->tree_root;
	for (d = 0; d < pfxlen && n; d++) {
		int bit;

		if (n->is_aggregate) {
			agg_node = n;
			agg_addr = walk_addr;
			agg_pfxlen = (uint8_t)d;
		}
		bit = (addr >> (31 - d)) & 1;
		if (bit)
			walk_addr |= (1u << (31 - d));
		n = n->child[bit];
	}

	if (agg_node) {
		uint32_t raddr;
		struct prefix agg_pfx = make_prefix_hbo(agg_addr, agg_pfxlen);

		remove_aggregate(NULL, &agg_pfx, bucket->grid, bucket->vni);
		if (sb->num_active_aggregates > 0)
			sb->num_active_aggregates--;
		agg_node->is_aggregate = false;

		raddr = agg_addr | (agg_pfxlen < 32 ? (1u << (31 - agg_pfxlen)) : 0);
		global_dynaggr_tnode_unsuppress_leaves(bgp_evpn, agg_node->child[0]);
		global_dynaggr_tnode_unsuppress_leaves(bgp_evpn, agg_node->child[1]);
		global_dynaggr_tnode_re_evaluate(bgp_evpn, agg_node->child[0], agg_addr,
						 agg_pfxlen + 1, sb, bucket);
		global_dynaggr_tnode_re_evaluate(bgp_evpn, agg_node->child[1], raddr,
						 agg_pfxlen + 1, sb, bucket);
	}

	global_dynaggr_tnode_rebuild_patricia(sb->tree_root);
}

/*
 * Check whether a global dynamic prefix-length tree has no runtime state left.
 */
static bool global_dynaggr_slice_is_empty(const struct global_dynaggr_slice_bucket *sb)
{
	return sb->tree_leaf_count == 0 && sb->num_active_aggregates == 0;
}

/*
 * Remove empty global dynamic runtime buckets after a withdraw.
 */
static void global_dynaggr_prune_empty_runtime(struct global_dynaggr_bucket *bucket,
					       struct global_dynaggr_slice_bucket *sb)
{
	struct global_dynaggr_slice_bucket **slice_pp;
	struct global_dynaggr_bucket **bucket_pp;

	if (!global_dynaggr_slice_is_empty(sb))
		return;

	for (slice_pp = &bucket->tree_slices; *slice_pp; slice_pp = &(*slice_pp)->next) {
		if (*slice_pp != sb)
			continue;
		*slice_pp = sb->next;
		global_dynaggr_tnode_free(sb->tree_root);
		XFREE(MTYPE_DYNAGGR, sb);
		break;
	}

	if (bucket->tree_slices)
		return;

	for (bucket_pp = &global_dynaggr_buckets; *bucket_pp; bucket_pp = &(*bucket_pp)->next) {
		if (*bucket_pp != bucket)
			continue;
		*bucket_pp = bucket->next;
		XFREE(MTYPE_DYNAGGR, bucket);
		return;
	}
}

/*
 * Free all global dynamic aggregation runtime state.
 */
static void global_free_runtime(void)
{
	struct bgp *bgp_evpn = bgp_get_evpn();
	struct global_dynaggr_bucket *bucket = global_dynaggr_buckets;

	while (bucket) {
		struct global_dynaggr_bucket *next_bucket = bucket->next;
		struct global_dynaggr_slice_bucket *slice = bucket->tree_slices;

		while (slice) {
			struct global_dynaggr_slice_bucket *next_slice = slice->next;

			global_dynaggr_tnode_clear_runtime(bgp_evpn, slice->tree_root, 0, 0, slice,
							   bucket);
			global_dynaggr_tnode_free(slice->tree_root);
			XFREE(MTYPE_DYNAGGR, slice);
			slice = next_slice;
		}

		XFREE(MTYPE_DYNAGGR, bucket);
		bucket = next_bucket;
	}

	global_dynaggr_buckets = NULL;
}

static void scoped_dynaggr_free_runtime(struct scoped_dynaggr_supernet *scoped)
{
	struct bgp *bgp_evpn = bgp_get_evpn();
	struct scoped_dynaggr_bucket *bucket = scoped->grid_buckets;

	while (bucket) {
		struct scoped_dynaggr_bucket *next = bucket->next;
		uint32_t i;

		for (i = 0; i < bucket->num_active_aggregates; i++)
			remove_aggregate(NULL, &bucket->active_aggregates[i], bucket->grid,
					 bucket->vni);

		if (bgp_evpn) {
			for (i = 0; i < bucket->total_slots; i++)
				unsuppress_path(bgp_evpn, bucket->slot_paths[i]);
		}

		XFREE(MTYPE_DYNAGGR, bucket->slot_paths);
		XFREE(MTYPE_DYNAGGR, bucket->active_aggregates);
		XFREE(MTYPE_DYNAGGR, bucket);
		bucket = next;
	}

	scoped->grid_buckets = NULL;
}

/* ===================================================================
 * Contiguity Detection (Dynamic Aggregation)
 * =================================================================== */

/*
 * Compute the aligned aggregate prefixes represented by occupied slots.
 */
static struct prefix *compute_contiguous_aggregates(const struct bgp_path_info **slot_paths,
						    uint32_t total_slots,
						    const struct scoped_dynaggr_supernet *scoped,
						    uint32_t *count)
{
	bool *remaining = XCALLOC(MTYPE_DYNAGGR, total_slots * sizeof(bool));
	uint32_t i;

	for (i = 0; i < total_slots; i++)
		remaining[i] = (slot_paths[i] != NULL);

	struct prefix *result = XCALLOC(MTYPE_DYNAGGR,
					(total_slots / 2 + 1) * sizeof(struct prefix));
	uint32_t num = 0;
	uint32_t block_size, start, s;

	for (block_size = total_slots; block_size >= 2; block_size >>= 1) {
		for (start = 0; start + block_size <= total_slots; start += block_size) {
			bool all_present = true;

			for (s = start; s < start + block_size; s++) {
				if (!remaining[s]) {
					all_present = false;
					break;
				}
			}
			if (!all_present)
				continue;

			uint32_t s_addr = ntohl(scoped->prefix.u.prefix4.s_addr);
			uint32_t slot_size = 1 << (32 - scoped->slice_prefixlen);
			uint32_t block_addr = s_addr + (start * slot_size);
			uint8_t pfxlen = scoped->slice_prefixlen;
			uint32_t bs = block_size;

			while (bs > 1) {
				pfxlen--;
				bs >>= 1;
			}

			result[num].family = AF_INET;
			result[num].u.prefix4.s_addr = htonl(block_addr);
			result[num].prefixlen = pfxlen;
			num++;

			for (s = start; s < start + block_size; s++)
				remaining[s] = false;
		}
	}

	XFREE(MTYPE_DYNAGGR, remaining);
	*count = num;
	return result;
}

/* ===================================================================
 * EVPN Type-5 Route Origination / Withdrawal
 * =================================================================== */

/*
 * Originate an EVPN Type-5 aggregate route for a grid and VNI.
 */
static void inject_aggregate(struct bgp *bgp, const struct prefix *aggr_pfx, struct grid *grid,
			     vni_t vni)
{
	struct bgp *bgp_evpn;
	struct prefix_evpn evp;
	struct prefix_rd prd;
	struct attr attr;
	struct attr *attr_new;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct bgp_labels bgp_labels = {};
	struct ecommunity_val eval;
	struct ecommunity ecom_encap;
	struct ecommunity *ecom;
	struct ecommunity *rt_ecom;
	struct community *comm;

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn)
		return;

	if (!dynaggr_cfg.has_community_asn || !dynaggr_cfg.has_site_id ||
	    !dynaggr_cfg.has_rd_id_base) {
		zlog_warn("DYNAGGR: site-id/community-asn/rd-id-base not configured, skip aggregate %pFX",
			  aggr_pfx);
		return;
	}

	build_type5_prefix_from_ip_prefix(&evp, aggr_pfx);
	form_auto_rd(bgp_evpn->router_id, grid->rd_id, &prd);

	/* Check if already installed */
	dest = bgp_evpn_global_node_lookup(bgp_evpn->rib[AFI_L2VPN][SAFI_EVPN], SAFI_EVPN, &evp,
					   &prd, NULL);
	if (dest) {
		for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
			if (!CHECK_FLAG(pi->flags, BGP_PATH_REMOVED) &&
			    bgp_evpn_is_path_local(bgp_evpn, pi) && get_vni_from_route(pi) == vni)
				break;
		}
		bgp_dest_unlock_node(dest);
		if (pi)
			return;
	}

	/* Build minimal attributes */
	memset(&attr, 0, sizeof(attr));
	bgp_attr_default_set(&attr, bgp_evpn, BGP_ORIGIN_IGP);

	/* Next-hop = 0.0.0.0 — intentionally broken, route-map overrides */
	memset(&attr.nexthop, 0, sizeof(attr.nexthop));
	memset(&attr.mp_nexthop_global_in, 0, sizeof(attr.mp_nexthop_global_in));
	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
	SET_FLAG(attr.flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP));

	/* Stamp grid community */
	{
		char comm_str[32];
		snprintf(comm_str, sizeof(comm_str), "%u:%u", dynaggr_cfg.community_asn,
			 grid->community_val);
		comm = community_str2com(comm_str);
		if (comm)
			bgp_attr_set_community(&attr, comm);
	}

	/* Encap = VXLAN extended community */
	memset(&ecom_encap, 0, sizeof(ecom_encap));
	encode_encap_extcomm(BGP_ENCAP_TYPE_VXLAN, &eval);
	ecom_encap.size = 1;
	ecom_encap.unit_size = ECOMMUNITY_SIZE;
	ecom_encap.val = (uint8_t *)eval.val;
	ecom = ecommunity_dup(&ecom_encap);
	bgp_attr_set_ecommunity(&attr, ecom);
	attr.encap_tunneltype = BGP_ENCAP_TYPE_VXLAN;

	/* Stamp RT = site_id:VNI on originated aggregates. */
	{
		char rt_str[32];
		snprintf(rt_str, sizeof(rt_str), "%u:%u", dynaggr_cfg.site_id, (uint32_t)vni);
		rt_ecom = ecommunity_str2com(rt_str, ECOMMUNITY_ROUTE_TARGET, 0);
		if (rt_ecom) {
			bgp_attr_set_ecommunity(&attr,
						ecommunity_merge(bgp_attr_get_ecommunity(&attr),
								 rt_ecom));
			ecommunity_free(&rt_ecom);
		}
	}

	/* Intern the attribute */
	attr_new = bgp_attr_intern(&attr);
	aspath_unintern(&attr.aspath);

	/* Get route node in global EVPN table */
	dest = bgp_evpn_global_node_get(bgp_evpn->rib[AFI_L2VPN][SAFI_EVPN], AFI_L2VPN, SAFI_EVPN,
					&evp, &prd, NULL);
	assert(dest);

	/* Create path_info */
	pi = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_STATIC, 0, bgp_evpn->peer_self, attr_new, dest);
	SET_FLAG(pi->flags, BGP_PATH_VALID);

	/* Set VNI label */
	bgp_evpn_path_info_extra_get(pi);
	vni2label(vni, &bgp_labels.label[0]);
	bgp_labels.num_labels = 1;
	bgp_labels_unintern(&pi->extra->labels);
	pi->extra->labels = bgp_labels_intern(&bgp_labels);

	/* Install and distribute */
	bgp_path_info_add(dest, pi);
	bgp_process(bgp_evpn, dest, pi, AFI_L2VPN, SAFI_EVPN);
	bgp_dest_unlock_node(dest);

	zlog_info("DYNAGGR: originated %pFX grid=%s vni=%u community=%u:%u rt=%u:%u", aggr_pfx,
		  grid->name, vni, dynaggr_cfg.community_asn, grid->community_val,
		  dynaggr_cfg.site_id, (uint32_t)vni);
}

/*
 * Withdraw an EVPN Type-5 aggregate route for a grid and VNI.
 */
static void remove_aggregate(struct bgp *bgp, const struct prefix *aggr_pfx, struct grid *grid,
			     vni_t vni)
{
	struct bgp *bgp_evpn;
	struct prefix_evpn evp;
	struct prefix_rd prd;
	struct bgp_dest *dest;
	struct bgp_path_info *pi;

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn)
		return;

	build_type5_prefix_from_ip_prefix(&evp, aggr_pfx);
	form_auto_rd(bgp_evpn->router_id, grid->rd_id, &prd);

	dest = bgp_evpn_global_node_lookup(bgp_evpn->rib[AFI_L2VPN][SAFI_EVPN], SAFI_EVPN, &evp,
					   &prd, NULL);
	if (!dest)
		return;

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next) {
		if (bgp_evpn_is_path_local(bgp_evpn, pi) && get_vni_from_route(pi) == vni)
			break;
	}

	if (!pi) {
		bgp_dest_unlock_node(dest);
		return;
	}

	bgp_path_info_mark_for_delete(dest, pi);
	bgp_process(bgp_evpn, dest, pi, AFI_L2VPN, SAFI_EVPN);
	bgp_dest_unlock_node(dest);

	zlog_info("DYNAGGR: withdrew %pFX grid=%s vni=%u", aggr_pfx, grid->name, vni);
}

/*
 * Originate configured static aggregates once EVPN is available.
 */
static void try_originate_static_aggregates(void)
{
	uint32_t i;

	if (static_aggregates_originated || !bm)
		return;

	if (!dynaggr_cfg.has_site_id || !dynaggr_cfg.has_community_asn ||
	    !dynaggr_cfg.has_rd_id_base)
		return;

	/* bgp_get_evpn() dereferences bm, so only call it after bm is valid. */
	if (!bgp_get_evpn())
		return;

	for (i = 0; i < num_static_aggregates; i++) {
		if (!static_aggregates[i].grid)
			continue;
		inject_aggregate(NULL, &static_aggregates[i].prefix, static_aggregates[i].grid,
				 static_aggregates[i].vni);
	}

	static_aggregates_originated = true;
}

/* ===================================================================
 * Dynamic Aggregation
 * =================================================================== */

/*
 * Check whether a scoped dynamic slot is covered by an active aggregate.
 */
static bool scoped_dynaggr_slot_is_covered(uint32_t slot, const struct prefix *aggregates,
					   uint32_t num_aggregates,
					   const struct scoped_dynaggr_supernet *scoped)
{
	uint32_t i;
	for (i = 0; i < num_aggregates; i++) {
		uint32_t agg_start = scoped_dynaggr_prefix_to_slot(&aggregates[i], scoped);
		uint32_t agg_size = 1 << (scoped->slice_prefixlen - aggregates[i].prefixlen);
		if (slot >= agg_start && slot < agg_start + agg_size)
			return true;
	}
	return false;
}

/*
 * Reconcile scoped dynamic aggregates and suppression for one bucket.
 */
static void scoped_dynaggr_reconcile(struct bgp *bgp, struct scoped_dynaggr_supernet *scoped,
				     struct scoped_dynaggr_bucket *bucket)
{
	struct bgp *bgp_evpn = bgp_get_evpn();
	struct prefix *new_aggrs;
	uint32_t new_count;
	uint32_t i, j;
	bool found;

	new_aggrs = compute_contiguous_aggregates((const struct bgp_path_info **)bucket->slot_paths,
						  bucket->total_slots, scoped, &new_count);

	/* Inject new aggregates */
	for (j = 0; j < new_count; j++) {
		found = false;
		if (bucket->active_aggregates) {
			for (i = 0; i < bucket->num_active_aggregates; i++) {
				if (prefix_same(&bucket->active_aggregates[i], &new_aggrs[j])) {
					found = true;
					break;
				}
			}
		}
		if (!found)
			inject_aggregate(bgp, &new_aggrs[j], bucket->grid, bucket->vni);
	}

	/* Remove aggregates that no longer exist */
	for (i = 0; i < bucket->num_active_aggregates; i++) {
		found = false;
		for (j = 0; j < new_count; j++) {
			if (prefix_same(&bucket->active_aggregates[i], &new_aggrs[j])) {
				found = true;
				break;
			}
		}
		if (!found)
			remove_aggregate(bgp, &bucket->active_aggregates[i], bucket->grid,
					 bucket->vni);
	}

	/* Update suppression: covered slots → suppress, uncovered → unsuppress */
	for (i = 0; i < bucket->total_slots; i++) {
		if (!bucket->slot_paths[i])
			continue;

		if (scoped_dynaggr_slot_is_covered(i, new_aggrs, new_count, scoped))
			suppress_path(bgp_evpn, bucket->slot_paths[i]);
		else
			unsuppress_path(bgp_evpn, bucket->slot_paths[i]);
	}

	if (bucket->active_aggregates)
		XFREE(MTYPE_DYNAGGR, bucket->active_aggregates);
	bucket->active_aggregates = new_aggrs;
	bucket->num_active_aggregates = new_count;
}

/*
 * Free a scoped runtime bucket when it no longer carries any state.
 */
static void scoped_dynaggr_prune_empty_bucket(struct scoped_dynaggr_supernet *scoped,
					      struct scoped_dynaggr_bucket *bucket)
{
	struct scoped_dynaggr_bucket **bucket_pp;

	if (!bucket || bucket->num_slices != 0 || bucket->num_active_aggregates != 0)
		return;

	for (bucket_pp = &scoped->grid_buckets; *bucket_pp; bucket_pp = &(*bucket_pp)->next) {
		if (*bucket_pp != bucket)
			continue;

		*bucket_pp = bucket->next;
		XFREE(MTYPE_DYNAGGR, bucket->slot_paths);
		XFREE(MTYPE_DYNAGGR, bucket->active_aggregates);
		XFREE(MTYPE_DYNAGGR, bucket);
		return;
	}
}

/*
 * Apply a route announce or withdraw to a scoped dynamic supernet.
 */
static void scoped_dynaggr_update(struct bgp *bgp, struct scoped_dynaggr_supernet *scoped,
				  const struct prefix *p, struct grid *grid, vni_t vni,
				  struct bgp_path_info *pi, bool is_announce)
{
	struct scoped_dynaggr_bucket *bucket;
	uint32_t slot;

	bucket = scoped_dynaggr_get_bucket(scoped, grid, vni);
	slot = scoped_dynaggr_prefix_to_slot(p, scoped);

	if (slot >= bucket->total_slots) {
		zlog_warn("DYNAGGR: [dynamic] slot %u out of range for %pFX", slot,
			  &scoped->prefix);
		return;
	}

	if (is_announce) {
		if (!bucket->slot_paths[slot]) {
			bucket->slot_paths[slot] = pi;
			bucket->num_slices++;
		}
		zlog_info("DYNAGGR: [dynamic] %pFX -> scoped %pFX grid=%s vni=%u slot=%u (%u slices)",
			  p, &scoped->prefix, grid->name, vni, slot, bucket->num_slices);
	} else {
		if (bucket->slot_paths[slot] == pi) {
			bucket->slot_paths[slot] = NULL;
			if (bucket->num_slices > 0)
				bucket->num_slices--;
		}
		zlog_info("DYNAGGR: [dynamic] %pFX withdrawn scoped %pFX grid=%s vni=%u slot=%u (%u slices)",
			  p, &scoped->prefix, grid->name, vni, slot, bucket->num_slices);
	}

	scoped_dynaggr_reconcile(bgp, scoped, bucket);
	scoped_dynaggr_prune_empty_bucket(scoped, bucket);
}

/*
 * Apply a route announce or withdraw to global dynamic aggregation.
 */
static void global_dynaggr_update(struct bgp *bgp, const struct global_dynaggr_rule *rule,
				  const struct prefix *p, struct grid *grid, vni_t vni,
				  struct bgp_path_info *pi, bool is_announce)
{
	struct bgp *bgp_evpn = bgp_get_evpn();
	struct global_dynaggr_bucket *bucket;
	struct global_dynaggr_slice_bucket *sb;

	if (!bgp_evpn)
		return;

	bucket = global_dynaggr_get_bucket(rule, grid, vni);
	sb = global_dynaggr_get_or_create_slice(bucket, p->prefixlen);

	if (is_announce)
		global_dynaggr_tree_announce(bgp_evpn, sb, bucket, p, pi);
	else {
		global_dynaggr_tree_withdraw(bgp_evpn, sb, bucket, p, pi);
		global_dynaggr_prune_empty_runtime(bucket, sb);
	}
}

/* ===================================================================
 * Dynamic Nexthop Registry
 *
 * When a configured anchor prefix is received as an EVPN Type-5, the
 * module treats it as a T2 identity/liveness announcement rather than
 * a tenant route. Per-grid lists of discovered T2 entries are maintained.
 * =================================================================== */

/*
 * Find or create the per-grid nexthop list.
 */
static struct dynaggr_nexthop_grid *dynaggr_nexthop_get_grid(struct grid *grid)
{
	struct dynaggr_nexthop_grid *g;

	for (g = dynaggr_nexthop_grids; g; g = g->next) {
		if (g->grid == grid)
			return g;
	}

	g = XCALLOC(MTYPE_DYNAGGR, sizeof(*g));
	g->grid = grid;
	g->next = dynaggr_nexthop_grids;
	dynaggr_nexthop_grids = g;
	return g;
}

/*
 * Register or update a T2 entry when an anchor route is announced.
 */
static void dynaggr_nexthop_announce(struct bgp_path_info *route, struct grid *grid, vni_t vni)
{
	struct dynaggr_nexthop_grid *ng;
	struct dynaggr_nexthop_entry *e;
	struct ethaddr rmac;
	bool has_rmac;

	if (!route || !route->attr || !route->peer || !route->peer->host || !grid)
		return;

	ng = dynaggr_nexthop_get_grid(grid);
	has_rmac = bgp_attr_rmac(route->attr, &rmac);

	/* Update existing entry from same peer if present */
	for (e = ng->entries; e; e = e->next) {
		if (strcmp(e->peer_host, route->peer->host) != 0)
			continue;
		e->vtep_ip = route->attr->mp_nexthop_global_in;
		e->vni = vni;
		if (has_rmac)
			e->rmac = rmac;
		zlog_info("DYNAGGR: nexthop-anchor: updated T2 peer=%s vtep=%pI4 vni=%u grid=%s",
			  e->peer_host, &e->vtep_ip, vni, grid->name);
		return;
	}

	e = XCALLOC(MTYPE_DYNAGGR, sizeof(*e));
	strlcpy(e->peer_host, route->peer->host, sizeof(e->peer_host));
	e->vtep_ip = route->attr->mp_nexthop_global_in;
	e->vni = vni;
	if (has_rmac)
		e->rmac = rmac;
	e->next = ng->entries;
	ng->entries = e;
	ng->count++;
	zlog_info("DYNAGGR: nexthop-anchor: registered T2 peer=%s vtep=%pI4 vni=%u grid=%s",
		  e->peer_host, &e->vtep_ip, vni, grid->name);
}

/*
 * Remove a T2 entry when its anchor route is withdrawn.
 */
static void dynaggr_nexthop_withdraw(struct bgp_path_info *route, struct grid *grid)
{
	struct dynaggr_nexthop_grid *ng;
	struct dynaggr_nexthop_entry **epp;

	if (!route || !route->peer || !route->peer->host || !grid)
		return;

	for (ng = dynaggr_nexthop_grids; ng; ng = ng->next) {
		if (ng->grid != grid)
			continue;
		for (epp = &ng->entries; *epp; epp = &(*epp)->next) {
			if (strcmp((*epp)->peer_host, route->peer->host) != 0)
				continue;
			{
				struct dynaggr_nexthop_entry *old = *epp;

				zlog_info("DYNAGGR: nexthop-anchor: removed T2 peer=%s grid=%s",
					  old->peer_host, grid->name);
				*epp = old->next;
				XFREE(MTYPE_DYNAGGR, old);
				if (ng->count > 0)
					ng->count--;
			}
			return;
		}
	}
}

/*
 * Free all dynamic nexthop registry state.
 */
static void dynaggr_nexthop_free_all(void)
{
	struct dynaggr_nexthop_grid *ng = dynaggr_nexthop_grids;

	while (ng) {
		struct dynaggr_nexthop_grid *next_ng = ng->next;
		struct dynaggr_nexthop_entry *e = ng->entries;

		while (e) {
			struct dynaggr_nexthop_entry *next_e = e->next;

			XFREE(MTYPE_DYNAGGR, e);
			e = next_e;
		}
		XFREE(MTYPE_DYNAGGR, ng);
		ng = next_ng;
	}
	dynaggr_nexthop_grids = NULL;
}

/* ===================================================================
 * Route Update Hook (Dynamic Aggregation only)
 * =================================================================== */

/*
 * Process EVPN route updates for scoped and global dynamic aggregation.
 */
static int dynaggr_route_update(struct bgp *bgp, afi_t afi, safi_t safi, struct bgp_dest *bn,
				struct bgp_path_info *old_route, struct bgp_path_info *new_route)
{
	const struct prefix *evpn_pfx;
	const struct prefix_evpn *evp;
	struct prefix ip_pfx;
	struct bgp_path_info *route;
	struct grid *grid;
	const struct global_dynaggr_rule *global_rule;
	vni_t vni;
	uint32_t i;
	bool is_announce = (new_route != NULL && old_route == NULL);
	bool is_withdraw = (old_route != NULL && new_route == NULL);

	if (afi != AFI_L2VPN || safi != SAFI_EVPN)
		return 0;

	if (!dynaggr_cfg.enabled)
		return 0;

	/* If EVPN became available after module load, originate static aggregates now. */
	try_originate_static_aggregates();

	if (num_scoped_dynaggr_supernets == 0 && num_global_dynaggr_rules == 0 &&
	    !dynaggr_nexthop_anchor_set)
		return 0;

	if (!is_announce && !is_withdraw)
		return 0;

	evpn_pfx = bgp_dest_get_prefix(bn);
	evp = (const struct prefix_evpn *)evpn_pfx;

	if (evp->prefix.route_type != BGP_EVPN_IP_PREFIX_ROUTE)
		return 0;

	route = is_announce ? new_route : old_route;

	/* Skip our own originated aggregates */
	if (route->peer == bgp->peer_self && route->type == ZEBRA_ROUTE_BGP &&
	    route->sub_type == BGP_ROUTE_STATIC)
		return 0;

	ip_prefix_from_type5_prefix(evp, &ip_pfx);
	if (ip_pfx.family != AF_INET)
		return 0;

	grid = get_grid_from_route(route);
	if (!grid)
		return 0;

	vni = get_vni_from_route(route);
	if (!vni)
		return 0;

	/* Dynamic nexthop anchor: treat matching route as T2 identity signal */
	if (dynaggr_nexthop_anchor_set && prefix_same(&ip_pfx, &dynaggr_nexthop_anchor)) {
		if (is_announce)
			dynaggr_nexthop_announce(route, grid, vni);
		else
			dynaggr_nexthop_withdraw(route, grid);
		return 0;
	}

	/* Dynamic aggregation: match scoped supernets */
	for (i = 0; i < num_scoped_dynaggr_supernets; i++) {
		if (!prefix_match(&scoped_dynaggr_supernets[i].prefix, &ip_pfx))
			continue;
		if (ip_pfx.prefixlen <= scoped_dynaggr_supernets[i].prefix.prefixlen)
			continue;

		scoped_dynaggr_update(bgp, &scoped_dynaggr_supernets[i], &ip_pfx, grid, vni, route,
				      is_announce);
		return 0;
	}

	global_rule = match_global_dynaggr_rule(route);
	if (global_rule) {
		global_dynaggr_update(bgp, global_rule, &ip_pfx, grid, vni, route, is_announce);
		return 0;
	}

	return 0;
}

/* ===================================================================
 * Show Command
 * =================================================================== */

/*
 * Build a scoped slot prefix from supernet and slot index.
 */
static struct prefix scoped_dynaggr_slot_prefix(const struct scoped_dynaggr_supernet *scoped,
						uint32_t slot)
{
	uint32_t base = ntohl(scoped->prefix.u.prefix4.s_addr);
	uint32_t slot_size = 1u << (32 - scoped->slice_prefixlen);

	return make_prefix_hbo(base + (slot * slot_size), scoped->slice_prefixlen);
}

/*
 * Check whether dynamic-aggr currently suppresses a contributor path.
 */
static bool dynaggr_path_is_suppressed(const struct bgp_path_info *pi)
{
	if (!pi || !pi->extra || !pi->extra->aggr_suppressors)
		return false;

	return listnode_lookup(pi->extra->aggr_suppressors, &dynaggr_suppressor_tag);
}

/*
 * Extract IPv4 prefix represented by an EVPN Type-5 path.
 */
static bool dynaggr_path_to_ip_prefix(const struct bgp_path_info *pi, struct prefix *ip_pfx)
{
	const struct prefix *evpn_pfx;
	const struct prefix_evpn *evp;

	if (!pi || !pi->net || !ip_pfx)
		return false;

	evpn_pfx = bgp_dest_get_prefix(pi->net);
	evp = (const struct prefix_evpn *)evpn_pfx;
	if (evp->prefix.route_type != BGP_EVPN_IP_PREFIX_ROUTE)
		return false;

	ip_prefix_from_type5_prefix(evp, ip_pfx);
	return ip_pfx->family == AF_INET;
}

/*
 * Dump one global dynamic tree node recursively.
 */
static void dynaggr_show_tnode_detail(struct vty *vty, const struct global_dynaggr_tnode *n,
				      uint32_t addr, uint8_t depth, const char *tree_prefix,
				      const char *edge_label, bool is_last)
{
	const struct global_dynaggr_tnode *view_n;
	uint32_t view_addr;
	uint8_t view_depth;
	char child_prefix[96];
	char content_prefix[96];
	bool have0;
	bool have1;
	bool route_suppressed;
	struct prefix node_pfx;

	if (!n)
		return;

	view_n = n;
	view_addr = addr;
	view_depth = depth;

	/*
	 * Render Patricia compression by walking compressed single-child edges
	 * before printing the node, so output follows the effective tree shape.
	 */
	if (n->num_skipped > 0) {
		uint8_t i;

		for (i = 0; i < n->num_skipped && view_n; i++) {
			uint8_t bit = (n->skip_bits >> (n->num_skipped - 1 - i)) & 1u;

			if (bit && view_depth < 32)
				view_addr |= (1u << (31 - view_depth));
			view_n = view_n->child[bit];
			view_depth++;
		}

		if (!view_n)
			return;
	}

	node_pfx = make_prefix_hbo(view_addr, view_depth);
	route_suppressed = view_n->path ? dynaggr_path_is_suppressed(view_n->path) : false;

	if (edge_label && edge_label[0] != '\0') {
		vty_out(vty,
			"%s%s%s node %pFX aggregate=%s route=%s leaf=%s compressed-skip=%u\n",
			tree_prefix ? tree_prefix : "", is_last ? "`--" : "|--", edge_label,
			&node_pfx, view_n->is_aggregate ? "yes" : "no",
			view_n->path ? (route_suppressed ? "suppressed" : "announced") : "none",
			view_n->path ? "yes" : "no", n->num_skipped);
		snprintf(content_prefix, sizeof(content_prefix), "%s%s",
			 tree_prefix ? tree_prefix : "", is_last ? "   " : "|  ");
	} else {
		vty_out(vty,
			"%snode %pFX aggregate=%s route=%s leaf=%s compressed-skip=%u\n",
			tree_prefix ? tree_prefix : "", &node_pfx,
			view_n->is_aggregate ? "yes" : "no",
			view_n->path ? (route_suppressed ? "suppressed" : "announced") : "none",
			view_n->path ? "yes" : "no", n->num_skipped);
		snprintf(content_prefix, sizeof(content_prefix), "%s",
			 tree_prefix ? tree_prefix : "");
	}

	have0 = (view_n->child[0] != NULL);
	have1 = (view_n->child[1] != NULL);
	snprintf(child_prefix, sizeof(child_prefix), "%s", content_prefix);

	if (have0)
		dynaggr_show_tnode_detail(vty, view_n->child[0], view_addr, view_depth + 1,
					  child_prefix, "0", !have1);
	if (have1)
		dynaggr_show_tnode_detail(vty, view_n->child[1],
					  view_addr | (view_depth < 32 ? (1u << (31 - view_depth))
								       : 0),
					  view_depth + 1, child_prefix, "1", true);
}

/*
 * Show configured and runtime dynamic aggregation state.
 */
DEFUN(show_dynamic_aggregate, show_dynamic_aggregate_cmd,
      "show dynamic-aggregate",
      SHOW_STR
      "Show dynamic EVPN Type-5 aggregation state\n")
{
	uint32_t i, j;
	struct scoped_dynaggr_bucket *b;

	vty_out(vty, "=== Grids ===\n");
	for (i = 0; i < num_grids; i++)
		vty_out(vty, "  %s (rt %s, community %u:%u)\n", grids[i].name,
			grids[i].rt ? grids[i].rt : "-", dynaggr_cfg.community_asn,
			grids[i].community_val);

	vty_out(vty, "\n=== Static Aggregates (permanent) ===\n");
	vty_out(vty, "%-20s %-10s %-8s\n", "Prefix", "Grid", "VNI");
	for (i = 0; i < num_static_aggregates; i++) {
		const char *grid_name = static_aggregates[i].grid ? static_aggregates[i].grid->name
								  : static_aggregates[i].grid_name;

		vty_out(vty, "%-20pFX %-10s %-8u\n", &static_aggregates[i].prefix,
			grid_name ? grid_name : "-", static_aggregates[i].vni);
	}

	vty_out(vty, "\n=== Dynamic Aggregation ===\n");
	for (i = 0; i < num_scoped_dynaggr_supernets; i++) {
		vty_out(vty, "Dynamic aggregate: %pFX (%u slots of /%u)\n",
			&scoped_dynaggr_supernets[i].prefix,
			scoped_dynaggr_supernets[i].total_slots,
			scoped_dynaggr_supernets[i].slice_prefixlen);

		for (b = scoped_dynaggr_supernets[i].grid_buckets; b; b = b->next) {
			vty_out(vty, "  Grid %s VNI %u: %u slices, %u aggregates\n", b->grid->name,
				b->vni, b->num_slices, b->num_active_aggregates);

			vty_out(vty, "    Bitmap: ");
			for (j = 0; j < b->total_slots; j++)
				vty_out(vty, "%c", b->slot_paths[j] ? '#' : '.');
			vty_out(vty, "\n");

			for (j = 0; j < b->num_active_aggregates; j++)
				vty_out(vty, "    -> %pFX\n", &b->active_aggregates[j]);
		}
	}

	vty_out(vty, "\n=== Global Dynamic Aggregation ===\n");
	for (struct global_dynaggr_rule *rule = global_dynaggr_rules; rule; rule = rule->next)
		vty_out(vty, "  Match community %s\n", rule->community_str);

	for (struct global_dynaggr_bucket *gb = global_dynaggr_buckets; gb; gb = gb->next) {
		struct global_dynaggr_slice_bucket *sb;

		vty_out(vty, "  Rule %s Grid %s VNI %u\n", gb->rule->community_str,
			gb->grid ? gb->grid->name : "-", gb->vni);
		for (sb = gb->tree_slices; sb; sb = sb->next)
			vty_out(vty, "    /%u leaves=%u aggregates=%u\n", sb->slice_prefixlen,
				sb->tree_leaf_count, sb->num_active_aggregates);
	}

	return CMD_SUCCESS;
}

/*
 * Show detailed configured and runtime dynamic aggregation state.
 */
DEFUN(show_dynamic_aggregate_detail, show_dynamic_aggregate_detail_cmd,
      "show dynamic-aggregate detail [scoped|global]",
      SHOW_STR
      "Show dynamic EVPN Type-5 aggregation state\n"
      "Show detailed dynamic aggregation internals\n"
      "Show detailed scoped dynamic aggregation runtime\n"
      "Show detailed global dynamic aggregation runtime\n")
{
	uint32_t i, j;
	struct scoped_dynaggr_bucket *b;
	int aidx;
	bool show_scoped = true;
	bool show_global = true;

	for (aidx = 0; aidx < argc; aidx++) {
		if (!argv[aidx]->arg)
			continue;
		if (strmatch(argv[aidx]->arg, "scoped")) {
			show_global = false;
			show_scoped = true;
			break;
		}
		if (strmatch(argv[aidx]->arg, "global")) {
			show_scoped = false;
			show_global = true;
			break;
		}
	}

	vty_out(vty, "=== Dynamic Aggregate Detail ===\n");
	vty_out(vty, "enabled=%s site-id=%u community-asn=%u rd-id-base=%u\n",
		dynaggr_cfg.enabled ? "yes" : "no", dynaggr_cfg.site_id, dynaggr_cfg.community_asn,
		dynaggr_cfg.rd_id_base);

	if (show_scoped) {
		vty_out(vty, "\n=== Scoped Dynamic Detail ===\n");
		for (i = 0; i < num_scoped_dynaggr_supernets; i++) {
			vty_out(vty, "Supernet %pFX slice-prefixlen /%u total-slots=%u\n",
				&scoped_dynaggr_supernets[i].prefix,
				scoped_dynaggr_supernets[i].slice_prefixlen,
				scoped_dynaggr_supernets[i].total_slots);

			for (b = scoped_dynaggr_supernets[i].grid_buckets; b; b = b->next) {
				vty_out(vty,
					"  Bucket grid=%s vni=%u slices=%u active-aggregates=%u\n",
					b->grid ? b->grid->name : "-", b->vni, b->num_slices,
					b->num_active_aggregates);

				for (j = 0; j < b->total_slots; j++) {
					struct bgp_path_info *pi = b->slot_paths[j];
					struct prefix slot_pfx;

					if (!pi)
						continue;

					slot_pfx = scoped_dynaggr_slot_prefix(&scoped_dynaggr_supernets[i],
								     j);
					if (dynaggr_path_to_ip_prefix(pi, &slot_pfx)) {
						vty_out(vty,
							"    slot[%u] contributor=%pFX suppressed=%s\n",
							j, &slot_pfx,
							dynaggr_path_is_suppressed(pi) ? "yes"
										       : "no");
					} else {
						slot_pfx = scoped_dynaggr_slot_prefix(&scoped_dynaggr_supernets[i],
								     j);
						vty_out(vty,
							"    slot[%u] contributor=%pFX suppressed=%s (fallback-prefix)\n",
							j, &slot_pfx,
							dynaggr_path_is_suppressed(pi) ? "yes"
										       : "no");
					}
				}

				for (j = 0; j < b->num_active_aggregates; j++)
					vty_out(vty, "    aggregate[%u]=%pFX announced=yes\n", j,
						&b->active_aggregates[j]);
			}
		}
	}

	if (show_global) {
		struct global_dynaggr_rule *rule;
		struct global_dynaggr_bucket *gb;
		struct global_dynaggr_slice_bucket *sb;

		vty_out(vty, "\n=== Global Dynamic Detail ===\n");
		for (rule = global_dynaggr_rules; rule; rule = rule->next)
			vty_out(vty, "Rule match-community=%s\n", rule->community_str);

		for (gb = global_dynaggr_buckets; gb; gb = gb->next) {
			vty_out(vty, "Bucket rule=%s grid=%s vni=%u\n",
				gb->rule ? gb->rule->community_str : "-",
				gb->grid ? gb->grid->name : "-", gb->vni);

			for (sb = gb->tree_slices; sb; sb = sb->next) {
				vty_out(vty, "  slice /%u leaves=%u active-aggregates=%u\n",
					sb->slice_prefixlen, sb->tree_leaf_count,
					sb->num_active_aggregates);
				dynaggr_show_tnode_detail(vty, sb->tree_root, 0, 0, "    ", "",
							  true);
			}
		}
	}

	return CMD_SUCCESS;
}

/* ===================================================================
	 * Config Helpers
	 * =================================================================== */

/*
 * Mark runtime origination state stale after configuration changes.
 */
static void dynaggr_reset_runtime_state(void)
{
	static_aggregates_originated = false;
}

/*
 * Check whether any config depends on the required base values.
 */
static bool dynaggr_has_dependent_config(void)
{
	return num_grids > 0 || num_static_aggregates > 0 || num_scoped_dynaggr_supernets > 0 ||
	       num_global_dynaggr_rules > 0;
}

/*
 * Reject removing a base value while dependent config remains.
 */
static int dynaggr_refuse_base_removal_if_needed(struct vty *vty)
{
	if (!dynaggr_has_dependent_config())
		return CMD_SUCCESS;

	vty_out(vty, "%% remove grid and aggregate entries first\n");
	return CMD_WARNING;
}

/*
 * Require site ID, community ASN, and RD ID base before dependent config.
 */
static int dynaggr_require_base_config(struct vty *vty)
{
	if (dynaggr_cfg.has_site_id && dynaggr_cfg.has_community_asn && dynaggr_cfg.has_rd_id_base)
		return CMD_SUCCESS;

	vty_out(vty, "%% site-id, community-asn, and rd-id-base must be configured first\n");
	return CMD_WARNING;
}

/*
 * Require base config and at least one grid before aggregate config.
 */
static int dynaggr_require_full_config(struct vty *vty)
{
	if (dynaggr_require_base_config(vty) != CMD_SUCCESS)
		return CMD_WARNING;

	if (num_grids > 0)
		return CMD_SUCCESS;

	vty_out(vty, "%% at least one grid must be configured first\n");
	return CMD_WARNING;
}

/*
 * Parse a standard community into its encoded 32-bit value.
 */
static int dynaggr_parse_standard_community(const char *text, uint32_t *community_val)
{
	char *sep;
	char *endp;
	char buf[32];
	unsigned long asn;
	unsigned long value;

	if (!text || !community_val || strlen(text) >= sizeof(buf))
		return CMD_WARNING;

	strlcpy(buf, text, sizeof(buf));
	sep = strchr(buf, ':');
	if (!sep || !sep[1])
		return CMD_WARNING;

	*sep = '\0';
	asn = strtoul(buf, &endp, 10);
	if (*endp != '\0' || asn > 65535)
		return CMD_WARNING;

	value = strtoul(sep + 1, &endp, 10);
	if (*endp != '\0' || value > 65535)
		return CMD_WARNING;

	*community_val = ((uint32_t)asn << 16) | (uint32_t)value;
	return CMD_SUCCESS;
}

/*
 * Add a global dynamic aggregation match rule.
 */
static int dynaggr_add_global_rule(const char *community_str)
{
	struct global_dynaggr_rule *rule;
	uint32_t community_val;

	if (dynaggr_parse_standard_community(community_str, &community_val) != CMD_SUCCESS)
		return CMD_WARNING;

	for (rule = global_dynaggr_rules; rule; rule = rule->next) {
		if (rule->match_community == community_val)
			return CMD_SUCCESS;
	}

	global_free_runtime();

	rule = XCALLOC(MTYPE_DYNAGGR, sizeof(*rule));
	rule->match_community = community_val;
	rule->community_str = XSTRDUP(MTYPE_DYNAGGR, community_str);
	rule->next = global_dynaggr_rules;
	global_dynaggr_rules = rule;
	num_global_dynaggr_rules++;
	return CMD_SUCCESS;
}

/*
 * Remove a global dynamic aggregation match rule.
 */
static int dynaggr_remove_global_rule(const char *community_str)
{
	struct global_dynaggr_rule **rule_pp;
	uint32_t community_val;

	if (dynaggr_parse_standard_community(community_str, &community_val) != CMD_SUCCESS)
		return CMD_WARNING;

	for (rule_pp = &global_dynaggr_rules; *rule_pp; rule_pp = &(*rule_pp)->next) {
		if ((*rule_pp)->match_community != community_val)
			continue;
		global_free_runtime();
		XFREE(MTYPE_DYNAGGR, (*rule_pp)->community_str);
		{
			struct global_dynaggr_rule *old = *rule_pp;
			*rule_pp = old->next;
			XFREE(MTYPE_DYNAGGR, old);
		}
		if (num_global_dynaggr_rules > 0)
			num_global_dynaggr_rules--;
		return CMD_SUCCESS;
	}

	return CMD_WARNING;
}

/*
 * Rebind static aggregate grid-name references after grid changes.
 */
static int dynaggr_rebuild_static_grid_refs(void)
{
	uint32_t i;
	int missing = 0;

	for (i = 0; i < num_static_aggregates; i++) {
		static_aggregates[i].grid = find_grid_by_name(static_aggregates[i].grid_name);
		if (!static_aggregates[i].grid) {
			zlog_err("DYNAGGR: grid '%s' not found for static aggregate %pFX",
				 static_aggregates[i].grid_name, &static_aggregates[i].prefix);
			missing++;
		}
	}

	return missing ? -1 : 0;
}

/*
 * Assign per-grid RD local IDs from the configured RD ID base.
 */
static void dynaggr_assign_grid_rd_ids(void)
{
	uint32_t i;

	if (!dynaggr_cfg.has_rd_id_base)
		return;

	rd_id_next = dynaggr_cfg.rd_id_base;
	for (i = 0; i < num_grids; i++)
		grids[i].rd_id = rd_id_next++;
}

/*
 * Parse the local-admin value from a route-target string.
 */
static int dynaggr_parse_rt_local_admin(const char *rt, uint16_t *community_val)
{
	const char *sep;
	char *endp;
	unsigned long value;

	if (!rt || !community_val)
		return CMD_WARNING;

	sep = strrchr(rt, ':');
	if (!sep || !sep[1])
		return CMD_WARNING;

	value = strtoul(sep + 1, &endp, 10);
	if (*endp != '\0' || value == 0 || value > 65535)
		return CMD_WARNING;

	*community_val = value;
	return CMD_SUCCESS;
}

/*
 * Add or update a grid definition.
 */
static int dynaggr_add_grid(const char *name, uint16_t community_val, const char *rt)
{
	struct grid *new_grids;
	struct grid *grid;
	char rt_buf[64];
	const char *rt_value = rt;

	if (!rt_value) {
		if (!dynaggr_cfg.has_community_asn)
			return CMD_WARNING;
		snprintf(rt_buf, sizeof(rt_buf), "%u:%u", dynaggr_cfg.community_asn, community_val);
		rt_value = rt_buf;
	}

	grid = find_grid_by_name(name);
	if (grid) {
		grid->community_val = community_val;
		XFREE(MTYPE_DYNAGGR, grid->rt);
		grid->rt = XSTRDUP(MTYPE_DYNAGGR, rt_value);
		dynaggr_reset_runtime_state();
		return CMD_SUCCESS;
	}

	new_grids = XREALLOC(MTYPE_DYNAGGR, grids, (num_grids + 1) * sizeof(*new_grids));
	grids = new_grids;
	grids[num_grids].name = XSTRDUP(MTYPE_DYNAGGR, name);
	grids[num_grids].community_val = community_val;
	grids[num_grids].rt = XSTRDUP(MTYPE_DYNAGGR, rt_value);
	grids[num_grids].rd_id = 0;
	num_grids++;
	dynaggr_assign_grid_rd_ids();
	dynaggr_reset_runtime_state();
	dynaggr_rebuild_static_grid_refs();
	return CMD_SUCCESS;
}

/*
 * Remove a grid definition if no aggregate still references it.
 */
static int dynaggr_remove_grid(const char *name)
{
	uint32_t i;

	for (i = 0; i < num_static_aggregates; i++) {
		if (strcmp(static_aggregates[i].grid_name, name) == 0)
			return CMD_WARNING;
	}

	for (i = 0; i < num_grids; i++) {
		if (strcmp(grids[i].name, name) != 0)
			continue;

		XFREE(MTYPE_DYNAGGR, grids[i].name);
		XFREE(MTYPE_DYNAGGR, grids[i].rt);
		if (i + 1 < num_grids)
			memmove(&grids[i], &grids[i + 1], (num_grids - i - 1) * sizeof(*grids));
		num_grids--;
		if (num_grids == 0) {
			XFREE(MTYPE_DYNAGGR, grids);
			grids = NULL;
		} else {
			grids = XREALLOC(MTYPE_DYNAGGR, grids, num_grids * sizeof(*grids));
		}
		dynaggr_assign_grid_rd_ids();
		dynaggr_reset_runtime_state();
		dynaggr_rebuild_static_grid_refs();
		return CMD_SUCCESS;
	}

	return CMD_WARNING;
}

/*
 * Add a static aggregate definition.
 */
static int dynaggr_add_static_aggregate(const struct prefix *prefix, const char *grid_name,
					vni_t vni)
{
	struct static_aggregate *new_static_aggrs;
	struct grid *grid = find_grid_by_name(grid_name);
	uint32_t i;

	if (!grid)
		return CMD_WARNING;

	for (i = 0; i < num_static_aggregates; i++) {
		if (prefix_same(&static_aggregates[i].prefix, prefix) &&
		    strcmp(static_aggregates[i].grid_name, grid_name) == 0 &&
		    static_aggregates[i].vni == vni)
			return CMD_SUCCESS;
	}

	new_static_aggrs = XREALLOC(MTYPE_DYNAGGR, static_aggregates,
				    (num_static_aggregates + 1) * sizeof(*new_static_aggrs));
	static_aggregates = new_static_aggrs;
	static_aggregates[num_static_aggregates].prefix = *prefix;
	static_aggregates[num_static_aggregates].grid = grid;
	static_aggregates[num_static_aggregates].grid_name = XSTRDUP(MTYPE_DYNAGGR, grid_name);
	static_aggregates[num_static_aggregates].vni = vni;
	num_static_aggregates++;
	dynaggr_reset_runtime_state();
	return CMD_SUCCESS;
}

/*
 * Remove a static aggregate definition.
 */
static int dynaggr_remove_static_aggregate(const struct prefix *prefix, const char *grid_name,
					   vni_t vni)
{
	uint32_t i;

	for (i = 0; i < num_static_aggregates; i++) {
		if (!prefix_same(&static_aggregates[i].prefix, prefix) ||
		    strcmp(static_aggregates[i].grid_name, grid_name) != 0 ||
		    static_aggregates[i].vni != vni)
			continue;

		remove_aggregate(NULL, &static_aggregates[i].prefix, static_aggregates[i].grid,
				 static_aggregates[i].vni);
		XFREE(MTYPE_DYNAGGR, static_aggregates[i].grid_name);
		if (i + 1 < num_static_aggregates)
			memmove(&static_aggregates[i], &static_aggregates[i + 1],
				(num_static_aggregates - i - 1) * sizeof(*static_aggregates));
		num_static_aggregates--;
		if (num_static_aggregates == 0) {
			XFREE(MTYPE_DYNAGGR, static_aggregates);
			static_aggregates = NULL;
		} else {
			static_aggregates =
				XREALLOC(MTYPE_DYNAGGR, static_aggregates,
					 num_static_aggregates * sizeof(*static_aggregates));
		}
		dynaggr_reset_runtime_state();
		return CMD_SUCCESS;
	}

	return CMD_WARNING;
}

/*
 * Add or update a scoped dynamic aggregation supernet.
 */
static int dynaggr_add_orphan_supernet(const struct prefix *prefix, uint8_t slice_prefixlen)
{
	struct scoped_dynaggr_supernet *new_orphans;
	uint8_t diff;
	uint32_t i;

	if (slice_prefixlen < prefix->prefixlen || slice_prefixlen > 32)
		return CMD_WARNING;

	for (i = 0; i < num_scoped_dynaggr_supernets; i++) {
		if (!prefix_same(&scoped_dynaggr_supernets[i].prefix, prefix))
			continue;
		scoped_dynaggr_supernets[i].slice_prefixlen = slice_prefixlen;
		diff = slice_prefixlen - prefix->prefixlen;
		if (diff >= 32)
			return CMD_WARNING;
		scoped_dynaggr_supernets[i].total_slots = 1u << diff;
		dynaggr_reset_runtime_state();
		return CMD_SUCCESS;
	}

	diff = slice_prefixlen - prefix->prefixlen;
	if (diff >= 32)
		return CMD_WARNING;
	new_orphans = XREALLOC(MTYPE_DYNAGGR, scoped_dynaggr_supernets,
			       (num_scoped_dynaggr_supernets + 1) * sizeof(*new_orphans));
	scoped_dynaggr_supernets = new_orphans;
	scoped_dynaggr_supernets[num_scoped_dynaggr_supernets].prefix = *prefix;
	scoped_dynaggr_supernets[num_scoped_dynaggr_supernets].slice_prefixlen = slice_prefixlen;
	scoped_dynaggr_supernets[num_scoped_dynaggr_supernets].total_slots = 1u << diff;
	scoped_dynaggr_supernets[num_scoped_dynaggr_supernets].grid_buckets = NULL;
	num_scoped_dynaggr_supernets++;
	dynaggr_reset_runtime_state();
	return CMD_SUCCESS;
}

/*
 * Clear all dynamic aggregation configuration and runtime data.
 */
static void dynaggr_clear_config_data(void)
{
	uint32_t i;

	for (i = 0; i < num_static_aggregates; i++) {
		remove_aggregate(NULL, &static_aggregates[i].prefix, static_aggregates[i].grid,
				 static_aggregates[i].vni);
		XFREE(MTYPE_DYNAGGR, static_aggregates[i].grid_name);
	}
	if (static_aggregates)
		XFREE(MTYPE_DYNAGGR, static_aggregates);
	static_aggregates = NULL;
	num_static_aggregates = 0;

	for (i = 0; i < num_scoped_dynaggr_supernets; i++)
		scoped_dynaggr_free_runtime(&scoped_dynaggr_supernets[i]);
	if (scoped_dynaggr_supernets)
		XFREE(MTYPE_DYNAGGR, scoped_dynaggr_supernets);
	scoped_dynaggr_supernets = NULL;
	num_scoped_dynaggr_supernets = 0;

	global_free_runtime();

	while (global_dynaggr_rules) {
		struct global_dynaggr_rule *next = global_dynaggr_rules->next;

		XFREE(MTYPE_DYNAGGR, global_dynaggr_rules->community_str);
		XFREE(MTYPE_DYNAGGR, global_dynaggr_rules);
		global_dynaggr_rules = next;
	}
	num_global_dynaggr_rules = 0;

	for (i = 0; i < num_grids; i++) {
		XFREE(MTYPE_DYNAGGR, grids[i].name);
		XFREE(MTYPE_DYNAGGR, grids[i].rt);
	}
	if (grids)
		XFREE(MTYPE_DYNAGGR, grids);
	grids = NULL;
	num_grids = 0;

	dynaggr_cfg.site_id = 0;
	dynaggr_cfg.community_asn = 0;
	dynaggr_cfg.rd_id_base = 0;
	dynaggr_cfg.has_site_id = false;
	dynaggr_cfg.has_community_asn = false;
	dynaggr_cfg.has_rd_id_base = false;
	dynaggr_nexthop_free_all();
	dynaggr_nexthop_anchor_set = false;
	memset(&dynaggr_nexthop_anchor, 0, sizeof(dynaggr_nexthop_anchor));
	dynaggr_reset_runtime_state();
}

static int dynaggr_fini(void)
{
	dynaggr_clear_config_data();
	dynaggr_cfg.enabled = false;
	return 0;
}

/*
 * Remove a scoped dynamic aggregation supernet if it has no active buckets.
 */
static int dynaggr_remove_orphan_supernet(const struct prefix *prefix)
{
	uint32_t i;

	for (i = 0; i < num_scoped_dynaggr_supernets; i++) {
		if (!prefix_same(&scoped_dynaggr_supernets[i].prefix, prefix))
			continue;

		if (scoped_dynaggr_supernets[i].grid_buckets)
			return CMD_WARNING;

		if (i + 1 < num_scoped_dynaggr_supernets)
			memmove(&scoped_dynaggr_supernets[i], &scoped_dynaggr_supernets[i + 1],
				(num_scoped_dynaggr_supernets - i - 1) *
					sizeof(*scoped_dynaggr_supernets));
		num_scoped_dynaggr_supernets--;
		if (num_scoped_dynaggr_supernets == 0) {
			XFREE(MTYPE_DYNAGGR, scoped_dynaggr_supernets);
			scoped_dynaggr_supernets = NULL;
		} else {
			scoped_dynaggr_supernets =
				XREALLOC(MTYPE_DYNAGGR, scoped_dynaggr_supernets,
					 num_scoped_dynaggr_supernets *
						 sizeof(*scoped_dynaggr_supernets));
		}
		dynaggr_reset_runtime_state();
		return CMD_SUCCESS;
	}

	return CMD_WARNING;
}

/*
 * Write running dynamic aggregation configuration.
 */
static int dynaggr_config_write(struct vty *vty)
{
	uint32_t i;

	if (!dynaggr_cfg.enabled)
		return 1;

	vty_out(vty, "dynamic-aggr\n");
	if (dynaggr_cfg.has_site_id)
		vty_out(vty, " site-id %u\n", dynaggr_cfg.site_id);
	if (dynaggr_cfg.has_community_asn)
		vty_out(vty, " community-asn %u\n", dynaggr_cfg.community_asn);
	if (dynaggr_cfg.has_rd_id_base)
		vty_out(vty, " rd-id-base %u\n", dynaggr_cfg.rd_id_base);

	for (i = 0; i < num_grids; i++) {
		if (grids[i].rt)
			vty_out(vty, " grid %s rt %s\n", grids[i].name, grids[i].rt);
		else
			vty_out(vty, " grid %s community %u\n", grids[i].name,
				grids[i].community_val);
	}

	for (i = 0; i < num_static_aggregates; i++)
		vty_out(vty, " static-aggregate prefix %pFX grid %s vni %u\n",
			&static_aggregates[i].prefix, static_aggregates[i].grid_name,
			static_aggregates[i].vni);

	for (i = 0; i < num_scoped_dynaggr_supernets; i++)
		vty_out(vty, " dynamic-aggregate prefix %pFX slice-prefixlen %u\n",
			&scoped_dynaggr_supernets[i].prefix,
			scoped_dynaggr_supernets[i].slice_prefixlen);

	for (struct global_dynaggr_rule *rule = global_dynaggr_rules; rule; rule = rule->next)
		vty_out(vty, " dynamic-aggregate global community %s\n", rule->community_str);

	if (dynaggr_nexthop_anchor_set)
		vty_out(vty, " enable dynamic-nexthop anchor %pFX\n", &dynaggr_nexthop_anchor);

	vty_out(vty, "!\n");
	return 1;
}

/*
 * Enter dynamic aggregation configuration mode.
 */
DEFUN(dynamic_aggr, dynamic_aggr_cmd,
	  "dynamic-aggr",
	  "Dynamic EVPN Type-5 aggregation configuration\n")
{
	dynaggr_cfg.enabled = true;
	vty->node = DYNAGGR_NODE;
	return CMD_SUCCESS;
}

/*
 * Disable dynamic aggregation and clear its configuration.
 */
DEFUN(no_dynamic_aggr, no_dynamic_aggr_cmd,
	  "no dynamic-aggr",
	  NO_STR
	  "Dynamic EVPN Type-5 aggregation configuration\n")
{
	uint32_t i;

	for (i = 0; i < num_scoped_dynaggr_supernets; i++) {
		if (scoped_dynaggr_supernets[i].grid_buckets) {
			vty_out(vty,
				"%% remove active dynamic-aggregate entries before disabling\n");
			return CMD_WARNING;
		}
	}

	dynaggr_clear_config_data();
	dynaggr_cfg.enabled = false;
	return CMD_SUCCESS;
}

/*
 * Configure the aggregate route-target site identifier.
 */
DEFUN(dynaggr_site_id, dynaggr_site_id_cmd,
	  "site-id (1-65535)",
	  "Aggregate route-target site identifier\n"
	  "Site identifier value\n")
{
	unsigned long value;
	int idx = 1;

	value = strtoul(argv[idx]->arg, NULL, 10);
	dynaggr_cfg.site_id = value;
	dynaggr_cfg.has_site_id = true;
	dynaggr_reset_runtime_state();
	return CMD_SUCCESS;
}

/*
 * Remove the aggregate route-target site identifier.
 */
DEFUN(no_dynaggr_site_id, no_dynaggr_site_id_cmd,
	  "no site-id [(1-65535)]",
	  NO_STR
	  "Aggregate route-target site identifier\n"
	  IGNORED_IN_NO_STR)
{
	if (dynaggr_refuse_base_removal_if_needed(vty) != CMD_SUCCESS)
		return CMD_WARNING;

	dynaggr_cfg.site_id = 0;
	dynaggr_cfg.has_site_id = false;
	dynaggr_reset_runtime_state();
	return CMD_SUCCESS;
}

/*
 * Configure the ASN used for grid standard communities.
 */
DEFUN(dynaggr_community_asn, dynaggr_community_asn_cmd,
	  "community-asn (1-65535)",
	  "Community ASN used for grid tagging\n"
	  "ASN value\n")
{
	unsigned long value;
	int idx = 1;

	value = strtoul(argv[idx]->arg, NULL, 10);
	dynaggr_cfg.community_asn = value;
	dynaggr_cfg.has_community_asn = true;
	dynaggr_reset_runtime_state();
	return CMD_SUCCESS;
}

/*
 * Configure the base local RD identifier for generated grid RDs.
 */
DEFUN(dynaggr_rd_id_base, dynaggr_rd_id_base_cmd,
	  "rd-id-base (1-65535)",
	  "Base local RD identifier for originated aggregates\n"
	  "Base local RD identifier value\n")
{
	unsigned long value;
	int idx = 1;

	value = strtoul(argv[idx]->arg, NULL, 10);
	dynaggr_cfg.rd_id_base = value;
	dynaggr_cfg.has_rd_id_base = true;
	dynaggr_assign_grid_rd_ids();
	dynaggr_reset_runtime_state();
	return CMD_SUCCESS;
}

/*
 * Remove the base local RD identifier.
 */
DEFUN(no_dynaggr_rd_id_base, no_dynaggr_rd_id_base_cmd,
	  "no rd-id-base [(1-65535)]",
	  NO_STR
	  "Base local RD identifier for originated aggregates\n"
	  IGNORED_IN_NO_STR)
{
	if (dynaggr_refuse_base_removal_if_needed(vty) != CMD_SUCCESS)
		return CMD_WARNING;

	dynaggr_cfg.rd_id_base = 0;
	dynaggr_cfg.has_rd_id_base = false;
	dynaggr_reset_runtime_state();
	return CMD_SUCCESS;
}

/*
 * Remove the ASN used for grid standard communities.
 */
DEFUN(no_dynaggr_community_asn, no_dynaggr_community_asn_cmd,
	  "no community-asn [(1-65535)]",
	  NO_STR
	  "Community ASN used for grid tagging\n"
	  IGNORED_IN_NO_STR)
{
	if (dynaggr_refuse_base_removal_if_needed(vty) != CMD_SUCCESS)
		return CMD_WARNING;

	dynaggr_cfg.community_asn = 0;
	dynaggr_cfg.has_community_asn = false;
	dynaggr_reset_runtime_state();
	return CMD_SUCCESS;
}

/*
 * Configure a grid with an explicit community value.
 */
DEFUN(dynaggr_grid, dynaggr_grid_cmd,
	  "grid WORD community (1-65535)",
	  "Grid definition\n"
	  "Grid name\n"
	  "Grid community value\n"
	  "Community numeric value\n")
{
	int idx_name = 1;
	int idx_value = 3;
	unsigned long value;

	if (dynaggr_require_base_config(vty) != CMD_SUCCESS)
		return CMD_WARNING;

	value = strtoul(argv[idx_value]->arg, NULL, 10);
	return dynaggr_add_grid(argv[idx_name]->arg, value, NULL);
}

/*
 * Configure a grid using the local-admin value from its route target.
 */
DEFUN(dynaggr_grid_rt, dynaggr_grid_rt_cmd,
	  "grid WORD rt WORD",
	  "Grid definition\n"
	  "Grid name\n"
	  "Grid route-target\n"
	  "Route-target value (for example ASN:VAL)\n")
{
	int idx_name = 1;
	int idx_rt = 3;
	uint16_t community_val;

	if (dynaggr_require_base_config(vty) != CMD_SUCCESS)
		return CMD_WARNING;

	if (dynaggr_parse_rt_local_admin(argv[idx_rt]->arg, &community_val) != CMD_SUCCESS) {
		vty_out(vty, "%% invalid rt value, expected something like 100:1\n");
		return CMD_WARNING;
	}

	return dynaggr_add_grid(argv[idx_name]->arg, community_val, argv[idx_rt]->arg);
}

/*
 * Remove a grid configured with an explicit community value.
 */
DEFUN(no_dynaggr_grid, no_dynaggr_grid_cmd,
	  "no grid WORD community [(1-65535)]",
	  NO_STR
	  "Grid definition\n"
	  "Grid name\n"
	  "Grid community value\n"
	  IGNORED_IN_NO_STR)
{
	int idx_name = 2;
	int ret;

	ret = dynaggr_remove_grid(argv[idx_name]->arg);
	if (ret != CMD_SUCCESS)
		vty_out(vty, "%% grid is in use or not found\n");
	return ret;
}

/*
 * Remove a grid configured with a route target.
 */
DEFUN(no_dynaggr_grid_rt, no_dynaggr_grid_rt_cmd,
	  "no grid WORD rt [WORD]",
	  NO_STR
	  "Grid definition\n"
	  "Grid name\n"
	  "Grid route-target\n"
	  IGNORED_IN_NO_STR)
{
	int idx_name = 2;
	int ret;

	ret = dynaggr_remove_grid(argv[idx_name]->arg);
	if (ret != CMD_SUCCESS)
		vty_out(vty, "%% grid is in use or not found\n");
	return ret;
}

/*
 * Configure a static aggregate prefix for a grid and VNI.
 */
DEFUN(dynaggr_static_aggregate, dynaggr_static_aggregate_cmd,
	  "static-aggregate prefix A.B.C.D/M grid WORD vni " CMD_VNI_RANGE,
	  "Static aggregate definition\n"
	  "Prefix keyword\n"
	  "IPv4 prefix\n"
	  "Grid binding\n"
	  "Grid name\n"
	  "L3VNI\n"
	  "VNI value\n")
{
	int idx_prefix = 2;
	int idx_grid = 4;
	int idx_vni = 6;
	struct prefix prefix;
	unsigned long vni;

	if (dynaggr_require_full_config(vty) != CMD_SUCCESS)
		return CMD_WARNING;

	if (!str2prefix(argv[idx_prefix]->arg, &prefix) || prefix.family != AF_INET)
		return CMD_WARNING;
	apply_mask(&prefix);
	vni = strtoul(argv[idx_vni]->arg, NULL, 10);
	if (dynaggr_add_static_aggregate(&prefix, argv[idx_grid]->arg, vni) != CMD_SUCCESS) {
		vty_out(vty, "%% grid not found\n");
		return CMD_WARNING;
	}
	try_originate_static_aggregates();

	return CMD_SUCCESS;
}

/*
 * Remove a static aggregate prefix for a grid and VNI.
 */
DEFUN(no_dynaggr_static_aggregate, no_dynaggr_static_aggregate_cmd,
	  "no static-aggregate prefix A.B.C.D/M grid WORD vni " CMD_VNI_RANGE,
	  NO_STR
	  "Static aggregate definition\n"
	  "Prefix keyword\n"
	  "IPv4 prefix\n"
	  "Grid binding\n"
	  "Grid name\n"
	  "L3VNI\n"
	  "VNI value\n")
{
	int idx_prefix = 3;
	int idx_grid = 5;
	int idx_vni = 7;
	struct prefix prefix;
	unsigned long vni;

	if (!str2prefix(argv[idx_prefix]->arg, &prefix) || prefix.family != AF_INET)
		return CMD_WARNING;
	apply_mask(&prefix);
	vni = strtoul(argv[idx_vni]->arg, NULL, 10);
	return dynaggr_remove_static_aggregate(&prefix, argv[idx_grid]->arg, vni);
}

/*
 * Configure a scoped dynamic aggregate supernet.
 */
DEFUN(dynaggr_dynamic_aggregate, dynaggr_dynamic_aggregate_cmd,
	  "dynamic-aggregate prefix A.B.C.D/M slice-prefixlen (0-32)",
	  "Dynamic aggregate definition\n"
	  "Prefix keyword\n"
	  "IPv4 supernet\n"
	  "Slice prefix length\n"
	  "Slice prefix length value\n")
{
	int idx_prefix = 2;
	int idx_slice = 4;
	struct prefix prefix;
	unsigned long slice_prefixlen;
	int ret;

	if (dynaggr_require_full_config(vty) != CMD_SUCCESS)
		return CMD_WARNING;

	if (!str2prefix(argv[idx_prefix]->arg, &prefix) || prefix.family != AF_INET)
		return CMD_WARNING;
	apply_mask(&prefix);
	slice_prefixlen = strtoul(argv[idx_slice]->arg, NULL, 10);
	ret = dynaggr_add_orphan_supernet(&prefix, slice_prefixlen);
	if (ret != CMD_SUCCESS)
		vty_out(vty, "%% invalid slice-prefixlen for dynamic-aggregate\n");
	return ret;
}

/*
 * Configure a global dynamic aggregate community match rule.
 */
DEFUN(dynaggr_global_dynamic_aggregate, dynaggr_global_dynamic_aggregate_cmd,
	  "dynamic-aggregate global community WORD",
	  "Dynamic aggregate definition\n"
	  "Global fallback aggregation\n"
	  "Standard community match\n"
	  "Community value (for example 501:123)\n")
{
	int idx_community = 3;
	int ret;

	if (dynaggr_require_full_config(vty) != CMD_SUCCESS)
		return CMD_WARNING;

	ret = dynaggr_add_global_rule(argv[idx_community]->arg);
	if (ret != CMD_SUCCESS)
		vty_out(vty, "%% invalid community value, expected ASN:VAL\n");
	return ret;
}

/*
 * Remove a scoped dynamic aggregate supernet.
 */
DEFUN(no_dynaggr_dynamic_aggregate, no_dynaggr_dynamic_aggregate_cmd,
	  "no dynamic-aggregate prefix A.B.C.D/M [slice-prefixlen (0-32)]",
	  NO_STR
	  "Dynamic aggregate definition\n"
	  "Prefix keyword\n"
	  "IPv4 supernet\n"
	  IGNORED_IN_NO_STR
	  IGNORED_IN_NO_STR)
{
	int idx_prefix = 3;
	struct prefix prefix;
	int ret;

	if (!str2prefix(argv[idx_prefix]->arg, &prefix) || prefix.family != AF_INET)
		return CMD_WARNING;
	apply_mask(&prefix);
	ret = dynaggr_remove_orphan_supernet(&prefix);
	if (ret != CMD_SUCCESS)
		vty_out(vty, "%% dynamic-aggregate is active or not found\n");
	return ret;
}

/*
 * Remove a global dynamic aggregate community match rule.
 */
DEFUN(no_dynaggr_global_dynamic_aggregate,
	  no_dynaggr_global_dynamic_aggregate_cmd,
	  "no dynamic-aggregate global community WORD",
	  NO_STR
	  "Dynamic aggregate definition\n"
	  "Global fallback aggregation\n"
	  "Standard community match\n"
	  "Community value (for example 501:123)\n")
{
	int idx_community = 4;
	int ret;

	ret = dynaggr_remove_global_rule(argv[idx_community]->arg);
	if (ret != CMD_SUCCESS)
		vty_out(vty, "%% global dynamic-aggregate not found\n");
	return ret;
}

/*
 * Originate static aggregates during late initialization when enabled.
 */
static int dynaggr_late_init(struct event_loop *tm)
{
	(void)tm;

	if (!dynaggr_cfg.enabled)
		return 0;

	try_originate_static_aggregates();
	return 0;
}

/*
 * Configure the anchor prefix used to identify T2 VTEP/RMAC announcements.
 */
DEFUN(dynaggr_nexthop_anchor_handler, dynaggr_nexthop_anchor_cmd,
	  "enable dynamic-nexthop anchor A.B.C.D/M",
	  "Enable feature\n"
	  "Dynamic nexthop T2 registration\n"
	  "Anchor prefix keyword\n"
	  "IPv4 anchor prefix (reserved, never used for tenant traffic)\n")
{
	struct prefix prefix;

	if (dynaggr_require_full_config(vty) != CMD_SUCCESS)
		return CMD_WARNING;

	if (!str2prefix(argv[3]->arg, &prefix) || prefix.family != AF_INET) {
		vty_out(vty, "%% invalid anchor prefix\n");
		return CMD_WARNING;
	}
	apply_mask(&prefix);
	dynaggr_nexthop_anchor = prefix;
	dynaggr_nexthop_anchor_set = true;
	return CMD_SUCCESS;
}

/*
 * Remove the anchor prefix configuration and clear the T2 registry.
 */
DEFUN(no_dynaggr_nexthop_anchor, no_dynaggr_nexthop_anchor_cmd,
	  "no enable dynamic-nexthop anchor [A.B.C.D/M]",
	  NO_STR
	  "Enable feature\n"
	  "Dynamic nexthop T2 registration\n"
	  "Anchor prefix keyword\n"
	  IGNORED_IN_NO_STR)
{
	dynaggr_nexthop_free_all();
	dynaggr_nexthop_anchor_set = false;
	memset(&dynaggr_nexthop_anchor, 0, sizeof(dynaggr_nexthop_anchor));
	return CMD_SUCCESS;
}

/*
 * Show the dynamic nexthop T2 registry per grid.
 */
DEFUN(show_dynamic_nexthop, show_dynamic_nexthop_cmd,
      "show dynamic-nexthop",
      SHOW_STR
      "Show dynamic T2 nexthop registry\n")
{
	struct dynaggr_nexthop_grid *ng;
	struct dynaggr_nexthop_entry *e;
	char rmac_str[18];

	if (!dynaggr_nexthop_anchor_set) {
		vty_out(vty, "Dynamic nexthop anchor not configured.\n");
		return CMD_SUCCESS;
	}

	vty_out(vty, "=== Dynamic Nexthop Registry ===\n");
	vty_out(vty, "Anchor: %pFX\n\n", &dynaggr_nexthop_anchor);

	for (ng = dynaggr_nexthop_grids; ng; ng = ng->next) {
		vty_out(vty, "  Grid %s (%u entr%s):\n",
			ng->grid->name, ng->count, ng->count == 1 ? "y" : "ies");
		for (e = ng->entries; e; e = e->next) {
			snprintf(rmac_str, sizeof(rmac_str),
				 "%02x:%02x:%02x:%02x:%02x:%02x",
				 e->rmac.octet[0], e->rmac.octet[1],
				 e->rmac.octet[2], e->rmac.octet[3],
				 e->rmac.octet[4], e->rmac.octet[5]);
			vty_out(vty, "    peer=%-20s vtep=%-15pI4 rmac=%s vni=%u\n",
				e->peer_host, &e->vtep_ip, rmac_str, e->vni);
		}
	}

	return CMD_SUCCESS;
}

/* ===================================================================
	 * Module Init
	 * =================================================================== */

/*
 * Register dynamic aggregation CLI, hooks, and startup state.
 */
void bgp_dynamic_aggr_init(void)
{
	dynaggr_assign_grid_rd_ids();
	dynaggr_rebuild_static_grid_refs();

	if (!dynaggr_cli_installed) {
		install_node(&dynaggr_node);
		install_default(DYNAGGR_NODE);
		install_element(CONFIG_NODE, &dynamic_aggr_cmd);
		install_element(CONFIG_NODE, &no_dynamic_aggr_cmd);
		/* Allow entering dynamic-aggr mode even if parser is in BGP context. */
		install_element(BGP_NODE, &dynamic_aggr_cmd);
		install_element(BGP_NODE, &no_dynamic_aggr_cmd);
		install_element(DYNAGGR_NODE, &dynaggr_site_id_cmd);
		install_element(DYNAGGR_NODE, &no_dynaggr_site_id_cmd);
		install_element(CONFIG_NODE, &dynaggr_site_id_cmd);
		install_element(CONFIG_NODE, &no_dynaggr_site_id_cmd);
		install_element(DYNAGGR_NODE, &dynaggr_community_asn_cmd);
		install_element(DYNAGGR_NODE, &no_dynaggr_community_asn_cmd);
		install_element(CONFIG_NODE, &dynaggr_community_asn_cmd);
		install_element(CONFIG_NODE, &no_dynaggr_community_asn_cmd);
		install_element(DYNAGGR_NODE, &dynaggr_rd_id_base_cmd);
		install_element(DYNAGGR_NODE, &no_dynaggr_rd_id_base_cmd);
		install_element(CONFIG_NODE, &dynaggr_rd_id_base_cmd);
		install_element(CONFIG_NODE, &no_dynaggr_rd_id_base_cmd);
		install_element(DYNAGGR_NODE, &dynaggr_grid_cmd);
		install_element(DYNAGGR_NODE, &dynaggr_grid_rt_cmd);
		install_element(DYNAGGR_NODE, &no_dynaggr_grid_cmd);
		install_element(DYNAGGR_NODE, &no_dynaggr_grid_rt_cmd);
		install_element(CONFIG_NODE, &dynaggr_grid_cmd);
		install_element(CONFIG_NODE, &dynaggr_grid_rt_cmd);
		install_element(CONFIG_NODE, &no_dynaggr_grid_cmd);
		install_element(CONFIG_NODE, &no_dynaggr_grid_rt_cmd);
		install_element(DYNAGGR_NODE, &dynaggr_static_aggregate_cmd);
		install_element(DYNAGGR_NODE, &no_dynaggr_static_aggregate_cmd);
		install_element(CONFIG_NODE, &dynaggr_static_aggregate_cmd);
		install_element(CONFIG_NODE, &no_dynaggr_static_aggregate_cmd);
		install_element(DYNAGGR_NODE, &dynaggr_dynamic_aggregate_cmd);
		install_element(DYNAGGR_NODE, &no_dynaggr_dynamic_aggregate_cmd);
		install_element(DYNAGGR_NODE, &dynaggr_global_dynamic_aggregate_cmd);
		install_element(DYNAGGR_NODE, &no_dynaggr_global_dynamic_aggregate_cmd);
		install_element(CONFIG_NODE, &dynaggr_dynamic_aggregate_cmd);
		install_element(CONFIG_NODE, &no_dynaggr_dynamic_aggregate_cmd);
		install_element(CONFIG_NODE, &dynaggr_global_dynamic_aggregate_cmd);
		install_element(CONFIG_NODE, &no_dynaggr_global_dynamic_aggregate_cmd);
		install_element(VIEW_NODE, &show_dynamic_aggregate_cmd);
		install_element(VIEW_NODE, &show_dynamic_aggregate_detail_cmd);
		install_element(DYNAGGR_NODE, &dynaggr_nexthop_anchor_cmd);
		install_element(DYNAGGR_NODE, &no_dynaggr_nexthop_anchor_cmd);
		install_element(CONFIG_NODE, &dynaggr_nexthop_anchor_cmd);
		install_element(CONFIG_NODE, &no_dynaggr_nexthop_anchor_cmd);
		install_element(VIEW_NODE, &show_dynamic_nexthop_cmd);
		dynaggr_cli_installed = true;
	}

	/* Register hook (Dynamic Aggregation) + show command */
	hook_register(frr_late_init, dynaggr_late_init);
	hook_register(frr_fini, dynaggr_fini);
	hook_register(bgp_route_update, dynaggr_route_update);

	zlog_info("DYNAGGR: loaded (%u grids, %u static-aggregates, %u dynamic-aggregates)",
		  num_grids, num_static_aggregates, num_scoped_dynaggr_supernets);
}
