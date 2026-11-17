// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Nexthop Fanout Module
 *
 * Hooks into the bgp_announce_peer event to set MED on routes
 * advertised to DPU peers, achieving per-DPU ECMP diversity
 * without route-map overhead.
 *
 * Configuration example (under router bgp / address-family l2vpn evpn):
 *
 *   router bgp 65000
 *    address-family l2vpn evpn
 *     nexthop-fanout threshold 18 total 36 metric 0 100 peer-group DPU1,DPU2
 *
 * This replaces the route-map approach:
 *
 *   route-map FANOUT permit 10        (no longer needed)
 *    match nexthop-fanout 18 36
 *    set metric 0
 *   route-map FANOUT permit 20
 *    set metric 100
 *
 * Copyright (C) 2026 Nick Bouliane
 */

#ifndef _BGP_FANOUT_H
#define _BGP_FANOUT_H

struct bgp;
struct vty;

extern void bgp_fanout_init(void);
extern void bgp_fanout_finish(void);
extern int bgp_fanout_config_write(struct bgp *bgp, struct vty *vty);

#endif /* _BGP_FANOUT_H */
