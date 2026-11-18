// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Nexthop Fanout Module
 *
 * Rewrites MED per-peer at packet generation time based on a
 * deterministic hash of (vtep_nexthop, dpu_ip).  Each DPU gets a
 * distinct set of "winner" nexthops for ECMP diversity.
 *
 * Configuration example (under router bgp / address-family l2vpn evpn):
 *
 *   router bgp 65000
 *    address-family l2vpn evpn
 *     nexthop-fanout threshold 18 total 36 metric 0 100 peer-group DPU1,DPU2
 */

#ifndef _BGP_FANOUT_H
#define _BGP_FANOUT_H

struct bgp;
struct vty;
struct peer;
struct attr;

extern void bgp_fanout_init(void);
extern void bgp_fanout_cleanup(struct bgp_fanout_config *cfg);
extern int bgp_fanout_config_write(struct bgp *bgp, struct vty *vty);

/*
 * Check if a peer belongs to one of the configured fanout peer groups.
 */
extern bool bgp_fanout_is_target_peer(const struct bgp *bgp,
				      const struct peer *peer);

/*
 * Compute the peer-independent partial hash key from the nexthop.
 * Returns true on success, false if hashing not applicable.
 */
extern bool bgp_fanout_partial_key(const struct attr *attr, uint32_t *key);

/*
 * Finalize the hash and return the MED for a specific peer.
 * partial_key comes from bgp_fanout_partial_key().
 * Returns UINT32_MAX if this peer is not in a configured fanout group
 * (caller should skip the MED overwrite in that case).
 */
extern uint32_t bgp_fanout_med_for_peer(const struct bgp *bgp,
					const struct peer *peer,
					uint32_t partial_key);

#endif /* _BGP_FANOUT_H */
