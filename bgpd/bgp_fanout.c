// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Nexthop Fanout Module
 *
 * Sets MED on routes advertised to DPU peers based on a deterministic
 * hash of (dpu_ip, vtep_nexthop, prefix).  Each DPU gets a distinct
 * set of "winner" routes (MED 0) for ECMP diversity.
 *
 * Configuration example:
 *
 *   router bgp 65000
 *    address-family l2vpn evpn
 *     nexthop-fanout threshold 18 total 36 metric 0 100 peer-group DPU1,DPU2
 *
 *   threshold 18  - hash bucket cutoff for "winner"
 *   total 36      - total hash bucket space
 *   metric 0 100  - MED for winners / losers
 *   peer-group DPU1,DPU2 - only apply to peers in these groups
 *
 * Copyright (C) 2026 Nick Bouliane
 */

#include <zebra.h>

#include "command.h"
#include "log.h"
#include "memory.h"
#include "sockunion.h"
#include "prefix.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_fanout.h"
#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_vty.h"

DEFINE_MTYPE_STATIC(BGPD, BGP_FANOUT_GROUP, "BGP fanout peer-group name");

/* ----------------------------------------------------------------
 * xxHash32 — inlined for zero-overhead hashing
 * Same algorithm as lib/jhash.c (which we replaced with xxHash32),
 * but self-contained here so the module has no hidden dependencies.
 * ---------------------------------------------------------------- */

#define XXH32_PRIME1 2654435761U
#define XXH32_PRIME2 2246822519U
#define XXH32_PRIME3 3266489917U
#define XXH32_PRIME4 668265263U
#define XXH32_PRIME5 374761393U

static inline uint32_t fanout_rotl32(uint32_t v, unsigned int n)
{
	return (v << n) | (v >> (32 - n));
}

static inline uint32_t fanout_load32le(const void *p)
{
	const uint8_t *b = p;

	return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
	       ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static inline uint32_t fanout_xxh32_round(uint32_t acc, uint32_t input)
{
	acc += input * XXH32_PRIME2;
	acc = fanout_rotl32(acc, 13);
	acc *= XXH32_PRIME1;
	return acc;
}

static inline uint32_t fanout_xxh32_avalanche(uint32_t h)
{
	h ^= h >> 15;
	h *= XXH32_PRIME2;
	h ^= h >> 13;
	h *= XXH32_PRIME3;
	h ^= h >> 16;
	return h;
}

static uint32_t fanout_xxh32(const void *input, size_t len, uint32_t seed)
{
	const uint8_t *ptr = input;
	const uint8_t *end = ptr + len;
	uint32_t h;

	if (len >= 16) {
		const uint8_t *limit = end - 16;
		uint32_t v1 = seed + XXH32_PRIME1 + XXH32_PRIME2;
		uint32_t v2 = seed + XXH32_PRIME2;
		uint32_t v3 = seed;
		uint32_t v4 = seed - XXH32_PRIME1;

		do {
			v1 = fanout_xxh32_round(v1, fanout_load32le(ptr));
			ptr += 4;
			v2 = fanout_xxh32_round(v2, fanout_load32le(ptr));
			ptr += 4;
			v3 = fanout_xxh32_round(v3, fanout_load32le(ptr));
			ptr += 4;
			v4 = fanout_xxh32_round(v4, fanout_load32le(ptr));
			ptr += 4;
		} while (ptr <= limit);

		h = fanout_rotl32(v1, 1) + fanout_rotl32(v2, 7) +
		    fanout_rotl32(v3, 12) + fanout_rotl32(v4, 18);
	} else {
		h = seed + XXH32_PRIME5;
	}

	h += len;

	while (ptr + 4 <= end) {
		h += fanout_load32le(ptr) * XXH32_PRIME3;
		h = fanout_rotl32(h, 17) * XXH32_PRIME4;
		ptr += 4;
	}

	while (ptr < end) {
		h += *ptr * XXH32_PRIME5;
		h = fanout_rotl32(h, 11) * XXH32_PRIME1;
		ptr++;
	}

	return fanout_xxh32_avalanche(h);
}

/* ----------------------------------------------------------------
 * Prefix hashing — extract the IP from EVPN Type-5 or plain prefix
 * ---------------------------------------------------------------- */

static bool fanout_addr_is_zero(const void *addr, size_t len)
{
	const uint8_t *b = addr;

	for (size_t i = 0; i < len; i++)
		if (b[i])
			return false;
	return true;
}

static bool fanout_hash_prefix(const struct prefix *prefix, uint32_t *key)
{
	const struct prefix_evpn *evp;
	const struct evpn_prefix_addr *ep;
	const void *addr;
	uint8_t pfx_addr[IPV6_MAX_BYTELEN] = {};
	uint8_t prefix_key[3];
	size_t prefix_addrlen;
	uint16_t prefixlen;
	int family, max_addrlen;

	if (!prefix || !key)
		return false;

	if (prefix->family == AF_EVPN) {
		evp = (const struct prefix_evpn *)prefix;
		if (evp->prefix.route_type != BGP_EVPN_IP_PREFIX_ROUTE ||
		    is_evpn_prefix_ipaddr_none(evp))
			return false;

		ep = &evp->prefix.prefix_addr;
		family = ipaddr_family(&ep->ip);
		max_addrlen = IPADDRSZ(&ep->ip);
		if (ep->ip_prefix_length > BSIZE(max_addrlen))
			return false;

		addr = ep->ip.ip.addrbytes;
		prefixlen = ep->ip_prefix_length;
		prefix_key[0] = family;
		prefix_key[1] = 0;
		prefix_key[2] = prefixlen;
	} else {
		max_addrlen = prefix_blen(prefix);
		if (max_addrlen <= 0 ||
		    prefix->prefixlen > (uint16_t)BSIZE(max_addrlen))
			return false;

		addr = &prefix->u.prefix;
		prefixlen = prefix->prefixlen;
		prefix_key[0] = prefix->family;
		prefix_key[1] = prefixlen >> 8;
		prefix_key[2] = prefixlen & 0xff;
	}

	if (!addr || max_addrlen > (int)sizeof(pfx_addr))
		return false;

	*key = fanout_xxh32(prefix_key, sizeof(prefix_key), *key);

	prefix_addrlen = PSIZE(prefixlen);
	memcpy(pfx_addr, addr, prefix_addrlen);
	if (prefixlen % 8)
		pfx_addr[prefix_addrlen - 1] &= 0xff << (8 - (prefixlen % 8));
	*key = fanout_xxh32(pfx_addr, prefix_addrlen, *key);

	return true;
}

/* ----------------------------------------------------------------
 * Hook callback — the core of the module
 * ---------------------------------------------------------------- */

/*
 * Check if a peer belongs to one of the configured fanout peer groups.
 */
static bool fanout_peer_group_match(const struct bgp_fanout_config *cfg,
				    const struct peer *peer)
{
	uint8_t i;

	if (!peer->group)
		return false;

	for (i = 0; i < cfg->num_groups; i++) {
		if (strcmp(peer->group->name, cfg->group_names[i]) == 0)
			return true;
	}
	return false;
}

/*
 * Extract the VTEP nexthop from the original path attributes.
 * Returns the address pointer and sets *len, or NULL on failure.
 */
static const void *fanout_get_vtep_nexthop(const struct attr *attr,
					   size_t *len)
{
	const void *nh;

	switch (attr->mp_nexthop_len) {
	case BGP_ATTR_NHLEN_IPV4:
	case BGP_ATTR_NHLEN_VPNV4:
		*len = IPV4_MAX_BYTELEN;
		return &attr->mp_nexthop_global_in;
	case BGP_ATTR_NHLEN_IPV6_GLOBAL:
	case BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL:
	case BGP_ATTR_NHLEN_VPNV6_GLOBAL:
	case BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL:
		nh = &attr->mp_nexthop_global;
		*len = IPV6_MAX_BYTELEN;
		if (fanout_addr_is_zero(nh, *len) &&
		    attr->mp_nexthop_global_in.s_addr != INADDR_ANY) {
			*len = IPV4_MAX_BYTELEN;
			return &attr->mp_nexthop_global_in;
		}
		return nh;
	default:
		return NULL;
	}
}

/*
 * bgp_announce_peer hook callback.
 *
 * Called for every (peer, route) pair that passes subgroup_announce_check().
 * For peers in configured fanout groups, compute hash and set MED.
 */
static int fanout_announce_hook(struct peer *peer, const struct prefix *p,
				struct bgp_path_info *pi, struct attr *attr)
{
	struct bgp *bgp;
	struct bgp_fanout_config *cfg;
	union sockunion peer_su = {};
	const uint8_t *peer_addr;
	size_t peer_addrlen;
	const void *nexthop;
	size_t nexthop_len;
	uint32_t key, bucket;

	bgp = peer->bgp;
	if (!bgp)
		return 0;

	cfg = &bgp->fanout_cfg;
	if (!cfg->enabled)
		return 0;

	if (!fanout_peer_group_match(cfg, peer))
		return 0;

	if (!pi || !pi->attr)
		return 0;

	/* DPU peer address from peer->host */
	if (!peer->host || str2sockunion(peer->host, &peer_su) < 0)
		return 0;

	peer_addr = sockunion_get_addr(&peer_su);
	peer_addrlen = sockunion_get_addrlen(&peer_su);
	if (!peer_addr || !peer_addrlen ||
	    fanout_addr_is_zero(peer_addr, peer_addrlen))
		return 0;

	/* VTEP nexthop from original (unmodified) path attributes */
	nexthop = fanout_get_vtep_nexthop(pi->attr, &nexthop_len);
	if (!nexthop || fanout_addr_is_zero(nexthop, nexthop_len))
		return 0;

	/* Hash: DPU IP, VTEP nexthop, prefix */
	key = fanout_xxh32(peer_addr, peer_addrlen, 0);
	key = fanout_xxh32(nexthop, nexthop_len, key);
	if (!fanout_hash_prefix(p, &key))
		return 0;

	bucket = key % cfg->total;
	if (bucket < cfg->threshold)
		attr->med = cfg->metric_winner;
	else
		attr->med = cfg->metric_loser;
	attr->flag |= ATTR_FLAG_BIT(BGP_ATTR_MULTI_EXIT_DISC);

	return 0;
}

/* ----------------------------------------------------------------
 * CLI commands
 * ---------------------------------------------------------------- */

DEFUN(bgp_nexthop_fanout,
      bgp_nexthop_fanout_cmd,
      "nexthop-fanout threshold (1-65535) total (1-65535) metric (0-4294967295) (0-4294967295) peer-group PGROUPS",
      "Nexthop fanout MED tagging for DPU ECMP diversity\n"
      "Hash bucket threshold for winner classification\n"
      "Threshold value\n"
      "Total hash bucket space\n"
      "Total value\n"
      "MED values for winner and loser routes\n"
      "MED for winner routes\n"
      "MED for loser routes\n"
      "Apply to peers in these peer groups\n"
      "Comma-separated list of peer-group names\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct bgp_fanout_config *cfg = &bgp->fanout_cfg;
	char *groups_str;
	char *token, *saveptr;
	uint8_t i;

	/* Free any previous group names */
	for (i = 0; i < cfg->num_groups; i++)
		XFREE(MTYPE_BGP_FANOUT_GROUP, cfg->group_names[i]);
	cfg->num_groups = 0;

	cfg->threshold = strtoul(argv[2]->arg, NULL, 10);
	cfg->total = strtoul(argv[4]->arg, NULL, 10);
	cfg->metric_winner = strtoul(argv[6]->arg, NULL, 10);
	cfg->metric_loser = strtoul(argv[7]->arg, NULL, 10);

	if (cfg->threshold > cfg->total) {
		vty_out(vty, "%% threshold must be <= total\n");
		cfg->enabled = false;
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Parse comma-separated peer-group list */
	groups_str = XSTRDUP(MTYPE_BGP_FANOUT_GROUP, argv[9]->arg);
	token = strtok_r(groups_str, ",", &saveptr);
	while (token && cfg->num_groups < BGP_FANOUT_MAX_GROUPS) {
		/* Trim leading whitespace */
		while (*token == ' ')
			token++;
		if (*token)
			cfg->group_names[cfg->num_groups++] =
				XSTRDUP(MTYPE_BGP_FANOUT_GROUP, token);
		token = strtok_r(NULL, ",", &saveptr);
	}
	XFREE(MTYPE_BGP_FANOUT_GROUP, groups_str);

	if (cfg->num_groups == 0) {
		vty_out(vty, "%% at least one peer-group is required\n");
		cfg->enabled = false;
		return CMD_WARNING_CONFIG_FAILED;
	}

	cfg->enabled = true;
	return CMD_SUCCESS;
}

DEFUN(no_bgp_nexthop_fanout,
      no_bgp_nexthop_fanout_cmd,
      "no nexthop-fanout",
      NO_STR
      "Disable nexthop fanout MED tagging\n")
{
	VTY_DECLVAR_CONTEXT(bgp, bgp);
	struct bgp_fanout_config *cfg = &bgp->fanout_cfg;
	uint8_t i;

	for (i = 0; i < cfg->num_groups; i++)
		XFREE(MTYPE_BGP_FANOUT_GROUP, cfg->group_names[i]);

	memset(cfg, 0, sizeof(*cfg));
	return CMD_SUCCESS;
}

/* ----------------------------------------------------------------
 * Config write / init / finish
 * ---------------------------------------------------------------- */

int bgp_fanout_config_write(struct bgp *bgp, struct vty *vty)
{
	struct bgp_fanout_config *cfg = &bgp->fanout_cfg;
	uint8_t i;

	if (!cfg->enabled)
		return 0;

	vty_out(vty, "  nexthop-fanout threshold %u total %u metric %u %u peer-group ",
		cfg->threshold, cfg->total,
		cfg->metric_winner, cfg->metric_loser);

	for (i = 0; i < cfg->num_groups; i++) {
		if (i > 0)
			vty_out(vty, ",");
		vty_out(vty, "%s", cfg->group_names[i]);
	}
	vty_out(vty, "\n");

	return 1;
}

void bgp_fanout_init(void)
{
	hook_register(bgp_announce_peer, fanout_announce_hook);

	install_element(BGP_EVPN_NODE, &bgp_nexthop_fanout_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_nexthop_fanout_cmd);
}

void bgp_fanout_finish(void)
{
	hook_unregister(bgp_announce_peer, fanout_announce_hook);
}
