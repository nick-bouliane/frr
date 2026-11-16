#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""Test deterministic EVPN Type-5 nexthop fanout in an outbound route-map."""

import functools
import json
import os
import sys

import pytest

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen


def setup_module(mod):
    topodef = {"s1": ("r1", "rr"), "s2": ("rr", "r2")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    tgen.net["r1"].cmd_raises(
        """
ip link add vxlan10 type vxlan id 10 dstport 4789 local 10.10.10.1 nolearning
ip link add br10 type bridge
ip link set dev vxlan10 master br10
ip link set dev br10 up
ip link set dev vxlan10 up
"""
    )
    for name, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, name, "frr.conf"))

    tgen.start_router()
    tgen.net["rr"].cmd_raises("ip route add 10.10.10.1/32 via 192.168.1.1")
    tgen.net["r2"].cmd_raises("ip route add 10.10.10.1/32 via 192.168.2.101")


def teardown_module(_mod):
    get_topogen().stop_topology()


def test_nexthop_fanout_filters_type5_routes():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    r2 = tgen.gears["r2"]
    expected_metrics = {
        "198.51.100.1": 0,
        "198.51.100.2": 0,
        "198.51.100.3": 0,
        "198.51.100.4": 100,
        "198.51.100.5": 0,
        "198.51.100.6": 0,
        "198.51.100.7": 100,
        "198.51.100.8": 100,
    }

    def _check_fanout_metrics():
        output = json.loads(r2.vtysh_cmd("show bgp l2vpn evpn json"))
        observed_metrics = {}

        for rd_routes in output.values():
            if not isinstance(rd_routes, dict):
                continue
            for route in rd_routes.values():
                if not isinstance(route, dict):
                    continue
                for path in route.get("paths", []):
                    ip = path.get("ip")
                    if ip in expected_metrics:
                        observed_metrics[ip] = path.get("metric")

        return topotest.json_cmp(observed_metrics, expected_metrics)

    _, result = topotest.run_and_expect(
        functools.partial(_check_fanout_metrics), None, count=60, wait=1
    )
    assert result is None, "EVPN Type-5 routes did not follow fanout bucket selection"


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))