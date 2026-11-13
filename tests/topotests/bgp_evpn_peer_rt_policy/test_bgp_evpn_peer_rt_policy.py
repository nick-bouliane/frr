#!/usr/bin/env python
# SPDX-License-Identifier: ISC

# Copyright (c) 2026 Nick Bouliane

"""
Test peer-rt-policy module with EVPN type-5 routes.

Topology:
    r1 (AS 65001) ---- r2 (AS 65002)

r2 advertises EVPN type-5 routes in two VRFs:
  - vrf-50:   RT 65002:50   (assigned value 50)   — network 10.0.50.1/32
  - vrf-1001: RT 65002:1001 (assigned value 1001)  — network 10.0.100.1/32

r1 has:
  - peer-rt-policy ALLOWED peer 192.168.1.2 permit rt 50
  - route-map PRP-IN permit 10 / match peer-rt-policy ALLOWED

Tests verify:
  1. r1 accepts routes with assigned-value 50 (allowed)
  2. r1 rejects routes with assigned-value 1001 (not allowed)
  3. After adding 1001 to the policy + soft-clear, routes appear
  4. After removing 50 from the policy + soft-clear, routes disappear
"""

import os
import sys
import json
import pytest
import functools

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger


def setup_module(mod):
    topodef = {"s1": ("r1", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    # vxlan + bridge for EVPN on r1
    tgen.net["r1"].cmd(
        """
ip link add vxlan50 type vxlan id 50 dstport 4789 local 10.10.10.1 nolearning
ip link add name br50 type bridge
ip link set dev vxlan50 master br50
ip link set up dev br50
ip link set up dev vxlan50
ip link add vxlan1001 type vxlan id 1001 dstport 4789 local 10.10.10.1 nolearning
ip link add name br1001 type bridge
ip link set dev vxlan1001 master br1001
ip link set up dev br1001
ip link set up dev vxlan1001
"""
    )

    # vxlan + bridge for EVPN on r2
    tgen.net["r2"].cmd(
        """
ip link add vxlan50 type vxlan id 50 dstport 4789 local 10.10.10.2 nolearning
ip link add name br50 type bridge
ip link set dev vxlan50 master br50
ip link set up dev br50
ip link set up dev vxlan50
ip link add vxlan1001 type vxlan id 1001 dstport 4789 local 10.10.10.2 nolearning
ip link add name br1001 type bridge
ip link set dev vxlan1001 master br1001
ip link set up dev br1001
ip link set up dev vxlan1001
"""
    )

    router_list = tgen.routers()
    for _, (rname, router) in enumerate(router_list.items(), 1):
        router.load_frr_config(os.path.join(CWD, "{}/frr.conf".format(rname)))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_initial_policy_allows_rt50_only():
    """
    With policy allowing only assigned-value 50:
    - Routes with RT *:50 should be accepted
    - Routes with RT *:1001 should be denied
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check_rt50_accepted():
        output = json.loads(
            r1.vtysh_cmd("show bgp l2vpn evpn json")
        )

        # Look for 10.0.50.1 (from vrf-50 with RT 65002:50)
        for rd, routes in output.get("advertisedRoutes", output).items():
            if not isinstance(routes, dict):
                continue
            for prefix, info in routes.items():
                if "10.0.50.1" in prefix:
                    return None  # found — success
        return "route 10.0.50.1 with RT *:50 not found"

    logger.info("Check that routes with RT assigned-value 50 are accepted")
    test_func = functools.partial(_check_rt50_accepted)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Route with allowed RT *:50 should be accepted"


def test_initial_policy_denies_rt1001():
    """
    Routes with RT *:1001 should be denied (not in policy).
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    def _check_rt1001_denied():
        output = json.loads(
            r1.vtysh_cmd("show bgp l2vpn evpn json")
        )

        for rd, routes in output.items():
            if not isinstance(routes, dict):
                continue
            for prefix in routes:
                if "10.0.100.1" in prefix:
                    return "route 10.0.100.1 with RT *:1001 found — should be denied"
        return None  # not found — success

    logger.info("Check that routes with RT assigned-value 1001 are denied")
    test_func = functools.partial(_check_rt1001_denied)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Route with unauthorized RT *:1001 should be denied"


def test_add_rt1001_and_softclear():
    """
    Add assigned-value 1001 to the policy, soft-clear inbound.
    Routes with RT *:1001 should now appear.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "\n".join([
            "configure",
            "peer-rt-policy ALLOWED peer 192.168.1.2 permit rt 1001",
        ])
    )
    r1.vtysh_cmd("clear bgp 192.168.1.2 soft in")

    def _check_rt1001_now_accepted():
        output = json.loads(
            r1.vtysh_cmd("show bgp l2vpn evpn json")
        )

        for rd, routes in output.items():
            if not isinstance(routes, dict):
                continue
            for prefix in routes:
                if "10.0.100.1" in prefix:
                    return None  # found — success
        return "route 10.0.100.1 with RT *:1001 still not found after policy update"

    logger.info("Check routes with RT *:1001 appear after adding to policy")
    test_func = functools.partial(_check_rt1001_now_accepted)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Route with RT *:1001 should appear after policy update + soft-clear"


def test_remove_rt50_and_softclear():
    """
    Remove assigned-value 50 from the policy, soft-clear inbound.
    Routes with RT *:50 should now be denied.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "\n".join([
            "configure",
            "no peer-rt-policy ALLOWED peer 192.168.1.2 permit rt 50",
        ])
    )
    r1.vtysh_cmd("clear bgp 192.168.1.2 soft in")

    def _check_rt50_now_denied():
        output = json.loads(
            r1.vtysh_cmd("show bgp l2vpn evpn json")
        )

        for rd, routes in output.items():
            if not isinstance(routes, dict):
                continue
            for prefix in routes:
                if "10.0.50.1" in prefix:
                    return "route 10.0.50.1 with RT *:50 still present — should be denied"
        return None  # not found — success

    def _check_rt1001_still_accepted():
        output = json.loads(
            r1.vtysh_cmd("show bgp l2vpn evpn json")
        )

        for rd, routes in output.items():
            if not isinstance(routes, dict):
                continue
            for prefix in routes:
                if "10.0.100.1" in prefix:
                    return None  # found — success
        return "route 10.0.100.1 with RT *:1001 disappeared"

    logger.info("Check routes with RT *:50 disappear after removal from policy")
    test_func = functools.partial(_check_rt50_now_denied)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, "Route with RT *:50 should be denied after policy removal + soft-clear"

    logger.info("Check routes with RT *:1001 still present")
    test_func = functools.partial(_check_rt1001_still_accepted)
    _, result = topotest.run_and_expect(test_func, None, count=30, wait=1)
    assert result is None, "Route with RT *:1001 should still be accepted"


def test_show_peer_rt_policy():
    """
    Verify the show command output reflects current state.
    After previous tests: only 1001 should remain for 192.168.1.2.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r1 = tgen.gears["r1"]

    output = r1.vtysh_cmd("show peer-rt-policy ALLOWED")

    assert "192.168.1.2" in output, "peer 192.168.1.2 should be in policy"
    assert "1001" in output, "assigned-value 1001 should be in policy"
    assert " 50 " not in output and " 50\n" not in output, \
        "assigned-value 50 should have been removed"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
