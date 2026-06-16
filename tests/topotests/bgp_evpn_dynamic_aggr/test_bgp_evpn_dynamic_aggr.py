#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Test EVPN Type-5 dynamic aggregation features.
"""

import functools
import json
import os
import re
import sys

import pytest

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import TopoRouter, Topogen, get_topogen
from lib.topolog import logger


EVPN_PREFIX_JSON = "show bgp l2vpn evpn route detail type prefix json"
GRID_A_RD = "10.255.0.1:50000"
GRID_B_RD = "10.255.0.1:50001"


def setup_module(mod):
    topodef = {"s1": ("leaf", "rr", "rx")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    tgen.net["leaf"].cmd_raises("ip link add vrf100 up type vrf table 100")
    tgen.net["leaf"].cmd_raises("ip link add br100 up master vrf100 type bridge")
    tgen.net["leaf"].cmd_raises(
        "ip link add vxlan100 up master br100 type vxlan id 100 "
        "dstport 4789 local 10.255.0.2 nolearning"
    )
    tgen.net["leaf"].cmd_raises("ip link add vrf200 up type vrf table 200")
    tgen.net["leaf"].cmd_raises("ip link add br200 up master vrf200 type bridge")
    tgen.net["leaf"].cmd_raises(
        "ip link add vxlan200 up master br200 type vxlan id 200 "
        "dstport 4789 local 10.255.0.2 nolearning"
    )

    for name, router in tgen.routers().items():
        router.load_frr_config(os.path.join(CWD, f"{name}/frr.conf"))

    tgen.start_router()


def teardown_module(_mod):
    get_topogen().stop_topology()


def _json_cmp(router: TopoRouter, command: str, expected: dict):
    raw_output = router.vtysh_cmd(command)
    try:
        output = json.loads(raw_output)
    except json.JSONDecodeError:
        return "invalid JSON output: {!r}".format(raw_output)
    return topotest.json_cmp(output, expected)


def _run_json_expect(router: TopoRouter, command: str, expected: dict, message: str):
    test_func = functools.partial(_json_cmp, router, command, expected)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, message


def _dynamic_aggr_output():
    tgen = get_topogen()
    return tgen.gears["rr"].vtysh_cmd("show dynamic-aggregate", isjson=False)


def _run_text_expect(patterns, message):
    def _match_output():
        output = _dynamic_aggr_output()
        missing = [pattern for pattern in patterns if not re.search(pattern, output)]
        return None if not missing else "missing {} in:\n{}".format(missing, output)

    _, result = topotest.run_and_expect(_match_output, None, count=60, wait=1)
    assert result is None, message


def _run_text_absent(patterns, message):
    def _match_output():
        output = _dynamic_aggr_output()
        present = [pattern for pattern in patterns if re.search(pattern, output)]
        return None if not present else "present {} in:\n{}".format(present, output)

    _, result = topotest.run_and_expect(_match_output, None, count=60, wait=1)
    assert result is None, message


def _run_text_count(pattern, expected_count, message):
    def _match_output():
        output = _dynamic_aggr_output()
        count = len(re.findall(pattern, output))
        if count == expected_count:
            return None
        return "expected {} matches for {}, got {} in:\n{}".format(
            expected_count, pattern, count, output
        )

    _, result = topotest.run_and_expect(_match_output, None, count=60, wait=1)
    assert result is None, message


def _assert_evpn_prefix(router, prefix_len, prefix, message, rd=GRID_A_RD, vni="100"):
    expected = {
        rd: {
            f"[5]:[0]:[{prefix_len}]:[{prefix}]": {
                "paths": [[{"vni": vni, "valid": True}]]
            }
        }
    }
    _run_json_expect(router, EVPN_PREFIX_JSON, expected, message)


def _evpn_prefix_present(router, prefix_len, prefix, rd=GRID_A_RD, vni="100"):
    try:
        output = json.loads(router.vtysh_cmd(EVPN_PREFIX_JSON))
    except json.JSONDecodeError:
        return False
    route = output.get(rd, {}).get(f"[5]:[0]:[{prefix_len}]:[{prefix}]")
    if not route:
        return False

    for path_group in route.get("paths", []):
        for path in path_group:
            if path.get("vni") == vni and path.get("valid") is True:
                return True
    return False


def _assert_no_evpn_prefix(router, prefix_len, prefix, message, rd=GRID_A_RD, vni="100"):
    def _missing():
        if not _evpn_prefix_present(router, prefix_len, prefix, rd, vni):
            return None
        return "{} {}/{} vni {} is still present".format(rd, prefix, prefix_len, vni)

    _, result = topotest.run_and_expect(_missing, None, count=60, wait=1)
    assert result is None, message


def _leaf_network(prefix, present=True, vrf="vrf100"):
    command = "network" if present else "no network"
    get_topogen().gears["leaf"].vtysh_cmd(
        f"""
configure terminal
 router bgp 65000 vrf {vrf}
  address-family ipv4 unicast
   {command} {prefix}
"""
    )


def _rr_config(commands):
    command_text = "\n".join(commands)
    return get_topogen().gears["rr"].vtysh_cmd(
        f"""
configure terminal
 dynamic-aggr
{command_text}
"""
    )


def test_static_aggregation():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Check configured static aggregate and originated Type-5 route")
    _run_text_expect(
        [r"192\.0\.2\.0/24\s+GRID-A\s+100"],
        "Static aggregate should be present in dynamic-aggr state",
    )
    _assert_evpn_prefix(
        tgen.gears["rr"], 24, "192.0.2.0", "Static aggregate should be originated"
    )

    logger.info("Check static aggregate duplicate config is idempotent")
    _rr_config([" static-aggregate prefix 192.0.2.0/24 grid GRID-A vni 100"])
    _run_text_count(
        r"192\.0\.2\.0/24\s+GRID-A\s+100",
        1,
        "Duplicate static aggregate config should not create duplicate state",
    )

    logger.info("Check static aggregate removal and re-add")
    _rr_config([" no static-aggregate prefix 192.0.2.0/24 grid GRID-A vni 100"])
    _run_text_absent(
        [r"192\.0\.2\.0/24\s+GRID-A\s+100"],
        "Static aggregate should be removed from dynamic-aggr state",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        24,
        "192.0.2.0",
        "Static aggregate route should be withdrawn after no static-aggregate",
    )

    _rr_config([" static-aggregate prefix 192.0.2.0/24 grid GRID-A vni 100"])
    _assert_evpn_prefix(
        tgen.gears["rr"], 24, "192.0.2.0", "Static aggregate should re-originate"
    )


def test_scoped_dynamic_aggregation():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Check scoped dynamic aggregation")
    _run_text_expect(
        [
            r"Dynamic aggregate: 10\.10\.0\.0/24 \(4 slots of /26\)",
            r"Grid GRID-A VNI 100: 2 slices, 1 aggregates",
            r"Bitmap: ##\.\.",
            r"-> 10\.10\.0\.0/25",
        ],
        "Scoped dynamic aggregate should be active",
    )
    _assert_evpn_prefix(
        tgen.gears["rr"],
        25,
        "10.10.0.0",
        "Scoped dynamic aggregate should be originated",
    )
    _assert_evpn_prefix(
        tgen.gears["rx"],
        25,
        "10.10.0.0",
        "Scoped dynamic aggregate should propagate to receiver",
    )

    logger.info("Withdraw one scoped contributor and check unsuppression")
    _leaf_network("10.10.0.64/26", present=False)
    _run_text_expect(
        [
            r"Dynamic aggregate: 10\.10\.0\.0/24 \(4 slots of /26\)",
            r"Grid GRID-A VNI 100: 1 slices, 0 aggregates",
            r"Bitmap: #\.\.\.",
        ],
        "Scoped dynamic aggregate should be withdrawn after losing a contributor",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        25,
        "10.10.0.0",
        "Scoped dynamic aggregate route should be withdrawn",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rx"],
        25,
        "10.10.0.0",
        "Scoped dynamic aggregate should withdraw from receiver",
    )

    logger.info("Re-add scoped contributor and check aggregate returns")
    _leaf_network("10.10.0.64/26")
    _run_text_expect(
        [
            r"Dynamic aggregate: 10\.10\.0\.0/24 \(4 slots of /26\)",
            r"Grid GRID-A VNI 100: 2 slices, 1 aggregates",
            r"Bitmap: ##\.\.",
            r"-> 10\.10\.0\.0/25",
        ],
        "Scoped dynamic aggregate should return after contributor re-add",
    )
    _assert_evpn_prefix(
        tgen.gears["rr"],
        25,
        "10.10.0.0",
        "Scoped dynamic aggregate route should re-originate",
    )
    _assert_evpn_prefix(
        tgen.gears["rx"],
        25,
        "10.10.0.0",
        "Scoped dynamic aggregate should re-propagate to receiver",
    )

    logger.info("Withdraw all scoped contributors and check runtime clears")
    _leaf_network("10.10.0.0/26", present=False)
    _leaf_network("10.10.0.64/26", present=False)
    _run_text_absent(
        [
            r"Dynamic aggregate: 10\.10\.0\.0/24 \(4 slots of /26\)\n  Grid GRID-A VNI 100:"
        ],
        "Scoped runtime bucket should be pruned after all contributors withdraw",
    )

    _leaf_network("10.10.0.0/26")
    _leaf_network("10.10.0.64/26")
    _assert_evpn_prefix(
        tgen.gears["rr"],
        25,
        "10.10.0.0",
        "Scoped dynamic aggregate should recover after full withdraw",
    )
    _assert_evpn_prefix(
        tgen.gears["rx"],
        25,
        "10.10.0.0",
        "Scoped dynamic aggregate should recover on receiver after full withdraw",
    )


def test_receiver_suppression_behavior():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Check receiver sees aggregate and not suppressed contributors")
    _assert_evpn_prefix(
        tgen.gears["rx"],
        25,
        "10.10.0.0",
        "Receiver should have scoped aggregate while both contributors exist",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rx"],
        26,
        "10.10.0.0",
        "Receiver should not see contributor while aggregate is active",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rx"],
        26,
        "10.10.0.64",
        "Receiver should not see second contributor while aggregate is active",
    )

    logger.info("Withdraw one contributor and verify unsuppressed route is propagated")
    _leaf_network("10.10.0.64/26", present=False)
    _assert_no_evpn_prefix(
        tgen.gears["rx"],
        25,
        "10.10.0.0",
        "Receiver aggregate should withdraw when contiguity breaks",
    )

    logger.info("Re-add contributor and verify aggregate returns with contributors suppressed")
    _leaf_network("10.10.0.64/26")
    _assert_evpn_prefix(
        tgen.gears["rx"],
        25,
        "10.10.0.0",
        "Receiver aggregate should return after contributor re-add",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rx"],
        26,
        "10.10.0.0",
        "Receiver should suppress contributor again after aggregate returns",
    )


def test_global_dynamic_aggregation():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Check global dynamic aggregation")
    _run_text_expect(
        [
            r"Match community 65000:900",
            r"Rule 65000:900 Grid GRID-A VNI 100",
            r"/25 leaves=4 aggregates=2",
            r"/26 leaves=\d+ aggregates=\d+",
        ],
        "Global dynamic aggregate should be active",
    )
    _assert_evpn_prefix(
        tgen.gears["rr"],
        24,
        "10.20.0.0",
        "Global dynamic aggregate should be originated",
    )
    _assert_evpn_prefix(
        tgen.gears["rx"],
        24,
        "10.20.0.0",
        "Global dynamic aggregate should propagate to receiver",
    )

    logger.info("Withdraw and re-add one global contributor")
    _leaf_network("10.20.0.128/25", present=False)
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        24,
        "10.20.0.0",
        "Global aggregate should withdraw after losing one /25 contributor",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rx"],
        24,
        "10.20.0.0",
        "Receiver global aggregate should withdraw after losing one /25 contributor",
    )
    _leaf_network("10.20.0.128/25")
    _assert_evpn_prefix(
        tgen.gears["rr"],
        24,
        "10.20.0.0",
        "Global aggregate should re-originate after contributor re-add",
    )
    _assert_evpn_prefix(
        tgen.gears["rx"],
        24,
        "10.20.0.0",
        "Receiver global aggregate should re-propagate after contributor re-add",
    )


def test_scoped_dynamic_corner_cases():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Check non-contiguous scoped slices do not aggregate")
    _run_text_expect(
        [
            r"Dynamic aggregate: 10\.40\.0\.0/24 \(4 slots of /26\)",
            r"Grid GRID-A VNI 100: 2 slices, 0 aggregates",
            r"Bitmap: #\.#\.",
        ],
        "Non-contiguous scoped slices should be tracked without an aggregate",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        25,
        "10.40.0.0",
        "Non-contiguous scoped slices should not create first /25 aggregate",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        25,
        "10.40.0.128",
        "Non-contiguous scoped slices should not create second /25 aggregate",
    )

    logger.info("Check full scoped slice set collapses to largest aggregate")
    _run_text_expect(
        [
            r"Dynamic aggregate: 10\.50\.0\.0/24 \(4 slots of /26\)",
            r"Grid GRID-A VNI 100: 4 slices, 1 aggregates",
            r"Bitmap: ####",
            r"-> 10\.50\.0\.0/24",
        ],
        "All scoped slices should collapse to the largest aggregate",
    )
    _assert_evpn_prefix(
        tgen.gears["rr"],
        24,
        "10.50.0.0",
        "Full scoped slice set should originate a /24 aggregate",
    )

    logger.info("Check VNI separation for identical scoped slices")
    _run_text_expect(
        [
            r"Dynamic aggregate: 10\.60\.0\.0/24 \(4 slots of /26\)",
            r"Grid GRID-A VNI 100: 2 slices, 1 aggregates",
            r"Grid GRID-A VNI 200: 2 slices, 1 aggregates",
        ],
        "Scoped buckets should be separated by VNI",
    )
    _assert_evpn_prefix(
        tgen.gears["rr"], 25, "10.60.0.0", "VNI 100 aggregate should exist"
    )
    _assert_evpn_prefix(
        tgen.gears["rr"],
        25,
        "10.60.0.0",
        "VNI 200 aggregate should exist",
        vni="200",
    )

    logger.info("Check grid/community separation")
    _run_text_expect(
        [
            r"Dynamic aggregate: 10\.70\.0\.0/24 \(4 slots of /26\)",
            r"Grid GRID-A VNI 100: 1 slices, 0 aggregates",
            r"Grid GRID-B VNI 100: 1 slices, 0 aggregates",
        ],
        "Scoped buckets should be separated by grid community",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        25,
        "10.70.0.0",
        "Different grid communities should not combine into GRID-A aggregate",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        25,
        "10.70.0.0",
        "Different grid communities should not combine into GRID-B aggregate",
        rd=GRID_B_RD,
    )

    logger.info("Check unknown grid community is ignored")
    _run_text_absent(
        [r"10\.80\.0\.0/26", r"Grid .*999"],
        "Route with an unknown grid community should not enter scoped runtime",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        25,
        "10.80.0.0",
        "Unknown grid community should not create a scoped aggregate",
    )

    logger.info("Check larger scoped bitmap boundaries with /28 slices")
    _run_text_expect(
        [
            r"Dynamic aggregate: 10\.120\.0\.0/24 \(16 slots of /28\)",
            r"Grid GRID-A VNI 100: 4 slices, 2 aggregates",
            r"-> 10\.120\.0\.0/27",
            r"-> 10\.120\.0\.128/27",
        ],
        "Large scoped bitmap should aggregate distant /28 pairs correctly",
    )
    _assert_evpn_prefix(
        tgen.gears["rr"],
        27,
        "10.120.0.0",
        "Scoped large-bitmap aggregate should originate first /27",
    )
    _assert_evpn_prefix(
        tgen.gears["rr"],
        27,
        "10.120.0.128",
        "Scoped large-bitmap aggregate should originate second /27",
    )
    _assert_evpn_prefix(
        tgen.gears["rx"],
        27,
        "10.120.0.0",
        "Receiver should learn first /27 aggregate from large bitmap",
    )
    _assert_evpn_prefix(
        tgen.gears["rx"],
        27,
        "10.120.0.128",
        "Receiver should learn second /27 aggregate from large bitmap",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rx"],
        28,
        "10.120.0.0",
        "Receiver should not receive contributing /28 while /27 aggregate is active",
    )


def test_global_dynamic_corner_cases():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Check grid-only route does not enter global aggregation")
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        24,
        "10.30.0.0",
        "Route without the global match community should not aggregate",
    )

    logger.info("Check global community without known grid is ignored")
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        24,
        "10.90.0.0",
        "Global match without a known grid community should not aggregate",
    )

    logger.info("Check mixed prefix lengths remain separate in global mode")
    _assert_evpn_prefix(
        tgen.gears["rr"],
        24,
        "10.100.0.0",
        "Two /25 global leaves should aggregate to /24",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        25,
        "10.100.0.0",
        "Extra /26 leaf should not corrupt the /25 aggregate tree",
    )

    logger.info("Check second global rule is independent")
    _run_text_expect(
        [
            r"Match community 65000:901",
            r"Rule 65000:901 Grid GRID-A VNI 100",
            r"/25 leaves=2 aggregates=1",
        ],
        "Second global rule should maintain its own runtime bucket",
    )
    _assert_evpn_prefix(
        tgen.gears["rr"],
        24,
        "10.110.0.0",
        "Second global rule should originate its own aggregate",
    )

    logger.info("Check global multi-level collapse from /26 leaves to /24 aggregate")
    _assert_evpn_prefix(
        tgen.gears["rr"],
        24,
        "10.130.0.0",
        "Global /26 contributors should collapse into /24 aggregate",
    )
    _assert_evpn_prefix(
        tgen.gears["rx"],
        24,
        "10.130.0.0",
        "Receiver should learn global /24 aggregate from /26 contributors",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rx"],
        26,
        "10.130.0.0",
        "Receiver should not receive /26 contributors after global aggregation",
    )


def test_dynamic_aggr_cli_guards():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Check destructive config deletes are guarded while active")
    output = _rr_config([" no grid GRID-A community 501"])
    assert "grid is in use or not found" in output

    output = _rr_config([" no dynamic-aggregate prefix 10.10.0.0/24"])
    assert "dynamic-aggregate is active or not found" in output

    output = tgen.gears["rr"].vtysh_cmd(
        """
configure terminal
 no dynamic-aggr
"""
    )
    assert "remove active dynamic-aggregate entries before disabling" in output


def test_dynamic_aggr_detail_cli():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Check dynamic-aggr detail introspection CLI")
    output = tgen.gears["rr"].vtysh_cmd("show dynamic-aggregate detail")
    assert "=== Dynamic Aggregate Detail ===" in output
    assert "=== Scoped Dynamic Detail ===" in output
    assert "=== Global Dynamic Detail ===" in output

    output = tgen.gears["rr"].vtysh_cmd("show dynamic-aggregate detail scoped")
    assert "=== Scoped Dynamic Detail ===" in output
    assert "=== Global Dynamic Detail ===" not in output

    output = tgen.gears["rr"].vtysh_cmd("show dynamic-aggregate detail global")
    assert "=== Global Dynamic Detail ===" in output
    assert "=== Scoped Dynamic Detail ===" not in output


def test_dynamic_aggr_config_write():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Check dynamic-aggr write-memory serialization")
    tgen.gears["rr"].vtysh_cmd("write memory")
    output = tgen.gears["rr"].vtysh_cmd("show running-config")

    assert "dynamic-aggr" in output
    assert " grid GRID-A rt 65000:501" in output
    assert " grid GRID-B rt 65000:502" in output
    assert " grid GRID-A rt 0:0" not in output
    assert " static-aggregate prefix 192.0.2.0/24 grid GRID-A vni 100" in output
    assert " dynamic-aggregate prefix 10.10.0.0/24 slice-prefixlen 26" in output
    assert " dynamic-aggregate prefix 10.120.0.0/24 slice-prefixlen 28" in output
    assert " dynamic-aggregate global community 65000:900" in output
    assert output.count(" static-aggregate prefix 192.0.2.0/24 grid GRID-A vni 100") == 1


def test_dynamic_aggr_session_reset_reconvergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Reset EVPN BGP sessions and verify aggregate reconvergence")
    tgen.gears["rr"].vtysh_cmd("clear bgp l2vpn evpn *")

    _assert_evpn_prefix(
        tgen.gears["rr"],
        24,
        "192.0.2.0",
        "Static aggregate should be present after EVPN session reset",
    )
    _assert_evpn_prefix(
        tgen.gears["rr"],
        25,
        "10.10.0.0",
        "Scoped aggregate should reconverge after EVPN session reset",
    )
    _assert_evpn_prefix(
        tgen.gears["rr"],
        24,
        "10.20.0.0",
        "Global aggregate should reconverge after EVPN session reset",
    )
    _assert_evpn_prefix(
        tgen.gears["rx"],
        24,
        "192.0.2.0",
        "Receiver should relearn static aggregate after EVPN session reset",
    )


def test_dynamic_aggr_peer_flap_reconvergence():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Flap RR-Leaf EVPN session and verify aggregate withdraw/reconvergence")
    tgen.gears["rr"].vtysh_cmd(
        """
configure terminal
 router bgp 65000
  address-family l2vpn evpn
   neighbor 10.0.0.2 shutdown
"""
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        24,
        "10.20.0.0",
        "RR global aggregate should withdraw while RR-Leaf EVPN session is down",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rx"],
        24,
        "10.20.0.0",
        "Receiver global aggregate should withdraw while RR-Leaf EVPN session is down",
    )

    tgen.gears["rr"].vtysh_cmd(
        """
configure terminal
 router bgp 65000
  address-family l2vpn evpn
   no neighbor 10.0.0.2 shutdown
"""
    )

    _assert_evpn_prefix(
        tgen.gears["rr"],
        24,
        "10.20.0.0",
        "RR global aggregate should return after RR-Leaf EVPN session recovers",
    )
    _assert_evpn_prefix(
        tgen.gears["rx"],
        24,
        "10.20.0.0",
        "Receiver global aggregate should return after RR-Leaf EVPN session recovers",
    )


def test_dynamic_aggr_full_cleanup_disable():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Withdraw contributors and fully delete dynamic-aggr config")
    vrf100_prefixes = [
        "10.10.0.0/26",
        "10.10.0.64/26",
        "10.20.0.0/25",
        "10.20.0.128/25",
        "10.30.0.0/25",
        "10.40.0.0/26",
        "10.40.0.128/26",
        "10.50.0.0/26",
        "10.50.0.64/26",
        "10.50.0.128/26",
        "10.50.0.192/26",
        "10.60.0.0/26",
        "10.60.0.64/26",
        "10.70.0.0/26",
        "10.70.0.64/26",
        "10.80.0.0/26",
        "10.90.0.0/25",
        "10.90.0.128/25",
        "10.100.0.0/25",
        "10.100.0.128/25",
        "10.100.0.64/26",
        "10.110.0.0/25",
        "10.110.0.128/25",
        "10.120.0.0/28",
        "10.120.0.16/28",
        "10.120.0.128/28",
        "10.120.0.144/28",
        "10.130.0.0/26",
        "10.130.0.64/26",
        "10.130.0.128/26",
        "10.130.0.192/26",
    ]
    for prefix in vrf100_prefixes:
        _leaf_network(prefix, present=False)

    _leaf_network("10.60.0.0/26", present=False, vrf="vrf200")
    _leaf_network("10.60.0.64/26", present=False, vrf="vrf200")

    logger.info("Wait for dynamic aggregates to withdraw before config cleanup")
    # Ensure route processing converges before issuing delete commands that
    # enforce 'active runtime' guards.
    _assert_no_evpn_prefix(
        tgen.gears["rr"], 25, "10.10.0.0", "Scoped 10.10 aggregate should withdraw"
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"], 24, "10.50.0.0", "Scoped 10.50 aggregate should withdraw"
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        25,
        "10.60.0.0",
        "Scoped 10.60 VNI100 aggregate should withdraw",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        25,
        "10.60.0.0",
        "Scoped 10.60 VNI200 aggregate should withdraw",
        vni="200",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"], 27, "10.120.0.0", "Scoped 10.120 first /27 should withdraw"
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        27,
        "10.120.0.128",
        "Scoped 10.120 second /27 should withdraw",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"], 24, "10.20.0.0", "Global 10.20 aggregate should withdraw"
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        24,
        "10.110.0.0",
        "Global 10.110 aggregate should withdraw",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        24,
        "10.130.0.0",
        "Global 10.130 aggregate should withdraw",
    )

    _rr_config(
        [
            " no static-aggregate prefix 192.0.2.0/24 grid GRID-A vni 100",
            " no dynamic-aggregate prefix 10.10.0.0/24",
            " no dynamic-aggregate prefix 10.40.0.0/24",
            " no dynamic-aggregate prefix 10.50.0.0/24",
            " no dynamic-aggregate prefix 10.60.0.0/24",
            " no dynamic-aggregate prefix 10.70.0.0/24",
            " no dynamic-aggregate prefix 10.80.0.0/24",
            " no dynamic-aggregate prefix 10.120.0.0/24",
            " no dynamic-aggregate global community 65000:900",
            " no dynamic-aggregate global community 65000:901",
            " no grid GRID-A rt 65000:501",
            " no grid GRID-B rt 65000:502",
        ]
    )

    output = tgen.gears["rr"].vtysh_cmd(
        """
configure terminal
 no dynamic-aggr
"""
    )
    assert "remove active dynamic-aggregate entries before disabling" not in output

    running = tgen.gears["rr"].vtysh_cmd("show running-config")
    assert "dynamic-aggr" not in running

    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        24,
        "192.0.2.0",
        "Static aggregate should be absent after full cleanup",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        25,
        "10.10.0.0",
        "Scoped aggregate should be absent after full cleanup",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rr"],
        24,
        "10.20.0.0",
        "Global aggregate should be absent after full cleanup",
    )
    _assert_no_evpn_prefix(
        tgen.gears["rx"],
        24,
        "10.20.0.0",
        "Receiver should not retain global aggregate after cleanup",
    )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))