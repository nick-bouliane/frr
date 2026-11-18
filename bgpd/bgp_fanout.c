// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Nexthop Fanout Module
 *
 * Sets MED on routes advertised to DPU peers based on a deterministic
 * hash of (dpu_ip, vtep_nexthop).  Each DPU gets a distinct
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
 */

#include <zebra.h>

#include "command.h"
#include "log.h"
#include "memory.h"
#include "sockunion.h"
#include "prefix.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_fanout.h"
#include "bgpd/bgp_vty.h"
#include "jhash.h"

DEFINE_MTYPE_STATIC(BGPD, BGP_FANOUT_GROUP, "BGP fanout peer-group name");

/* ----------------------------------------------------------------
 * Address helpers
 * ---------------------------------------------------------------- */

static bool fanout_addr_is_zero(const void *addr, size_t len)
{
	const uint8_t *b = addr;

	for (size_t i = 0; i < len; i++)
		if (b[i])
			return false;
	return true;
}

/* ----------------------------------------------------------------
 * Peer group matching
 * ---------------------------------------------------------------- */

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

bool bgp_fanout_is_target_peer(const struct bgp *bgp, const struct peer *peer)
{
	if (!bgp || !peer || !bgp->fanout_cfg.enabled)
		return false;
	return fanout_peer_group_match(&bgp->fanout_cfg, peer);
}

/* ----------------------------------------------------------------
 * VTEP nexthop extraction
 * ---------------------------------------------------------------- */

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

	groups_str = XSTRDUP(MTYPE_BGP_FANOUT_GROUP, argv[9]->arg);
	token = strtok_r(groups_str, ",", &saveptr);
	while (token && cfg->num_groups < BGP_FANOUT_MAX_GROUPS) {
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

	vty_out(vty,
		"  nexthop-fanout threshold %u total %u metric %u %u peer-group ",
		cfg->threshold, cfg->total, cfg->metric_winner,
		cfg->metric_loser);

	for (i = 0; i < cfg->num_groups; i++) {
		if (i > 0)
			vty_out(vty, ",");
		vty_out(vty, "%s", cfg->group_names[i]);
	}
	vty_out(vty, "\n");

	return 1;
}

bool bgp_fanout_partial_key(const struct attr *attr, uint32_t *key)
{
	const void *nexthop;
	size_t nexthop_len;

	if (!attr || !key)
		return false;

	nexthop = fanout_get_vtep_nexthop(attr, &nexthop_len);
	if (!nexthop || fanout_addr_is_zero(nexthop, nexthop_len))
		return false;

	*key = jhash(nexthop, nexthop_len, 0);
	return true;
}

uint32_t bgp_fanout_med_for_peer(const struct bgp *bgp,
				 const struct peer *peer,
				 uint32_t partial_key)
{
	const struct bgp_fanout_config *cfg;
	union sockunion peer_su = {};
	const uint8_t *peer_addr;
	size_t peer_addrlen;
	uint32_t key;

	cfg = &bgp->fanout_cfg;

	if (!fanout_peer_group_match(cfg, peer))
		return UINT32_MAX;

	if (!peer->host || str2sockunion(peer->host, &peer_su) < 0)
		return cfg->metric_loser;

	peer_addr = sockunion_get_addr(&peer_su);
	peer_addrlen = sockunion_get_addrlen(&peer_su);
	if (!peer_addr || !peer_addrlen)
		return cfg->metric_loser;

	key = jhash(peer_addr, peer_addrlen, partial_key);
	if ((key % cfg->total) < cfg->threshold)
		return cfg->metric_winner;
	return cfg->metric_loser;
}

void bgp_fanout_cleanup(struct bgp_fanout_config *cfg)
{
	uint8_t i;

	for (i = 0; i < cfg->num_groups; i++)
		XFREE(MTYPE_BGP_FANOUT_GROUP, cfg->group_names[i]);
	memset(cfg, 0, sizeof(*cfg));
}

void bgp_fanout_init(void)
{
	install_element(BGP_EVPN_NODE, &bgp_nexthop_fanout_cmd);
	install_element(BGP_EVPN_NODE, &no_bgp_nexthop_fanout_cmd);
}
