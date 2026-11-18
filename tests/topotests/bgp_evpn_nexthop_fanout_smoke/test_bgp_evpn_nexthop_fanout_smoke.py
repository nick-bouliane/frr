#!/usr/bin/env python
# SPDX-License-Identifier: ISC

"""Smoke-test EVPN nexthop fanout configuration and per-peer MED rewrite."""

import json
import os
import tempfile

import pytest

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

# pylint: disable=C0413
CWD = os.path.dirname(os.path.realpath(__file__))
import sys

sys.path.append(os.path.join(CWD, "../"))

from lib import topotest
from lib.topogen import Topogen, get_topogen

CONFIG_DIR = None
PREFIX = "198.51.100.1"


def build_topo(tgen):
    vtep = tgen.add_router("vtep")
    rr = tgen.add_router("rr")
    dpu = tgen.add_router("dpu")
    tgen.add_link(vtep, rr)
    tgen.add_link(rr, dpu)


def _configs():
    vtep = """\
frr defaults traditional
hostname vtep
log stdout
vrf vrf-10
 vni 10
 exit-vrf
interface lo
 ip address 10.10.10.1/32
interface loop10 vrf vrf-10
 ip address 198.51.100.1/32
interface vtep-eth0
 ip address 192.168.1.1/24
router bgp 65001
 bgp router-id 10.10.10.1
 no bgp default ipv4-unicast
 no bgp ebgp-requires-policy
 neighbor 192.168.1.101 remote-as 65000
 neighbor 192.168.1.101 capability extended-nexthop
 address-family l2vpn evpn
  neighbor 192.168.1.101 activate
  advertise-all-vni
 exit-address-family
router bgp 65001 vrf vrf-10
 no bgp network import-check
 address-family ipv4 unicast
  network 198.51.100.1/32
 exit-address-family
 address-family l2vpn evpn
  rd 65000:1
  route-target both 65000:10
  advertise ipv4 unicast
 exit-address-family
!
"""
    rr = """\
frr defaults traditional
hostname rr
log stdout
interface rr-eth0
 ip address 192.168.1.101/24
interface rr-eth1
 ip address 192.168.2.101/24
router bgp 65000
 bgp router-id 192.168.0.101
 no bgp default ipv4-unicast
 no bgp ebgp-requires-policy
 neighbor 192.168.1.1 remote-as 65001
 neighbor 192.168.1.1 capability extended-nexthop
 neighbor DPU peer-group
 neighbor DPU remote-as external
 neighbor DPU capability extended-nexthop
 neighbor 192.168.2.2 peer-group DPU
 address-family l2vpn evpn
  neighbor 192.168.1.1 activate
  neighbor DPU activate
  nexthop-fanout threshold 1 total 1 metric 7 11 peer-group DPU
 exit-address-family
!
"""
    dpu = """\
frr defaults traditional
hostname dpu
log stdout
interface lo
 ip address 10.10.10.2/32
interface dpu-eth0
 ip address 192.168.2.2/24
router bgp 65002
 bgp router-id 10.10.10.2
 no bgp default ipv4-unicast
 no bgp ebgp-requires-policy
 neighbor 192.168.2.101 remote-as 65000
 neighbor 192.168.2.101 capability extended-nexthop
 address-family l2vpn evpn
  neighbor 192.168.2.101 activate
 exit-address-family
!
"""
    return {"vtep": vtep, "rr": rr, "dpu": dpu}


def setup_module(_module):
    global CONFIG_DIR

    tgen = Topogen(build_topo, __name__)
    tgen.start_topology()

    tgen.net["vtep"].cmd_raises(
        """ip link add vrf-10 type vrf table 10
ip link set dev vrf-10 up
ip link add loop10 type dummy
ip link set dev loop10 master vrf-10
ip link set dev loop10 up
ip link add br10 type bridge
ip link set dev br10 master vrf-10
ip link set dev br10 up
ip link add vxlan10 type vxlan id 10 dstport 4789 local 10.10.10.1 nolearning
ip link set dev vxlan10 master br10
ip link set dev vxlan10 up
"""
    )

    CONFIG_DIR = tempfile.TemporaryDirectory(prefix="bgp-evpn-fanout-smoke-")
    for name, config in _configs().items():
        config_path = os.path.join(CONFIG_DIR.name, f"{name}.conf")
        with open(config_path, "w", encoding="utf-8") as config_file:
            config_file.write(config)
        tgen.gears[name].load_frr_config(config_path)

    tgen.start_router()
    tgen.net["rr"].cmd_raises("ip route add 10.10.10.1/32 via 192.168.1.1")
    tgen.net["dpu"].cmd_raises("ip route add 10.10.10.1/32 via 192.168.2.101")


def teardown_module(_module):
    tgen = get_topogen()
    tgen.stop_topology()
    if CONFIG_DIR:
        CONFIG_DIR.cleanup()


def _evpn_metric(router):
    output = json.loads(router.vtysh_cmd("show bgp l2vpn evpn json"))
    for routes in output.values():
        if not isinstance(routes, dict):
            continue
        for route in routes.values():
            if not isinstance(route, dict):
                continue
            for path in route.get("paths", []):
                if path.get("ip") == PREFIX:
                    return path.get("metric")
    return None


def _sessions_established():
    tgen = get_topogen()
    for name in ("vtep", "dpu"):
        summary = json.loads(tgen.gears[name].vtysh_cmd("show bgp l2vpn evpn summary json"))
        neighbors = summary.get("peers", {})
        if not neighbors or any(peer.get("state") != "Established" for peer in neighbors.values()):
            return {name: neighbors}
    return None


def test_fanout_config_loads_and_rewrites_median():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    _, result = topotest.run_and_expect(_sessions_established, None, count=60, wait=0.5)
    assert result is None, f"EVPN sessions did not establish: {result}"

    _, metric = topotest.run_and_expect(
        lambda: _evpn_metric(tgen.gears["dpu"]), 7, count=60, wait=0.5
    )
    assert metric == 7, f"expected fanout winner MED 7, got {metric}"


if __name__ == "__main__":
    import sys

    sys.exit(pytest.main(["-s"] + sys.argv[1:]))
