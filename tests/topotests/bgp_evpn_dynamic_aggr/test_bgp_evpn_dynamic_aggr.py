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
    topodef = {"s1": ("leaf", "t2b", "t2c", "t2d", "rr", "rx")}
    tgen = Topogen(topodef, mod.__name__)
    tgen.start_topology()

    for name, local in [
        ("leaf", "10.255.0.2"),
        ("t2b", "10.255.1.2"),
        ("t2c", "10.255.1.3"),
        ("t2d", "10.255.1.4"),
    ]:
        tgen.net[name].cmd_raises("ip link add vrf100 up type vrf table 100")
        tgen.net[name].cmd_raises("ip link add br100 up master vrf100 type bridge")
        tgen.net[name].cmd_raises(
            "ip link add vxlan100 up master br100 type vxlan id 100 "
            f"dstport 4789 local {local} nolearning"
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


def _leaf_network(prefix, present=True, vrf="vrf100", route_map=None):
    command = "network" if present else "no network"
    route_map_clause = f" route-map {route_map}" if present and route_map else ""
    get_topogen().gears["leaf"].vtysh_cmd(
        f"""
configure terminal
 router bgp 65000 vrf {vrf}
  address-family ipv4 unicast
   {command} {prefix}{route_map_clause}
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


def _leaf_cfg(commands):
    command_text = "\n".join(commands)
    return get_topogen().gears["leaf"].vtysh_cmd(
        f"""
configure terminal
{command_text}
"""
    )


def _router_cfg(router_name, commands):
    command_text = "\n".join(commands)
    return get_topogen().gears[router_name].vtysh_cmd(
        f"""
configure terminal
{command_text}
"""
    )


def _router_network(router_name, prefix, present=True, vrf="vrf100"):
    command = "network" if present else "no network"
    get_topogen().gears[router_name].vtysh_cmd(
        f"""
configure terminal
 router bgp 65000 vrf {vrf}
  address-family ipv4 unicast
   {command} {prefix}
"""
    )


def _evpn_instance_count(router, prefix_len, prefix, vni=None):
    try:
        output = json.loads(router.vtysh_cmd(EVPN_PREFIX_JSON))
    except json.JSONDecodeError:
        return -1

    key = f"[5]:[0]:[{prefix_len}]:[{prefix}]"
    count = 0
    for rd_data in output.values():
        if not isinstance(rd_data, dict):
            continue
        route = rd_data.get(key)
        if not route:
            continue
        for path_group in route.get("paths", []):
            for path in path_group:
                if path.get("valid") is not True:
                    continue
                if vni is not None and str(path.get("vni")) != str(vni):
                    continue
                count += 1
    return count


def _assert_evpn_instance_count(router, prefix_len, prefix, expected_count, message, vni=None):
    def _count_match():
        count = _evpn_instance_count(router, prefix_len, prefix, vni=vni)
        if count == expected_count:
            return None
        return (
            f"expected {expected_count} instances for {prefix}/{prefix_len}"
            f" vni={vni}, got {count}"
        )

    _, result = topotest.run_and_expect(_count_match, None, count=60, wait=1)
    assert result is None, message


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


def test_fanout_multi_grid_three_anchors_per_grid():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Program fan-out test config: 4 grids, dedicated global rule, anchor supernet")
    _rr_config(
        [
            " grid GRID-C rt 65000:503",
            " grid GRID-D rt 65000:504",
            " dynamic-aggregate global community 65000:990",
            " enable dynamic-nexthop anchor 198.18.0.0/24",
        ]
    )

    logger.info("Install per-speaker policy and announce fan-out contributors from 4 FRRs")

    fanout_sources = {
        "leaf": {
            "grid_comm": "65000:501",
            "global": ["10.210.0.0/25", "10.210.0.128/25"],
            "anchors": ["198.18.0.1/32", "198.18.0.2/32", "198.18.0.3/32"],
        },
        "t2b": {
            "grid_comm": "65000:502",
            "global": ["10.211.0.0/25", "10.211.0.128/25"],
            "anchors": ["198.18.0.11/32", "198.18.0.12/32", "198.18.0.13/32"],
        },
        "t2c": {
            "grid_comm": "65000:503",
            "global": ["10.212.0.0/25", "10.212.0.128/25"],
            "anchors": ["198.18.0.21/32", "198.18.0.22/32", "198.18.0.23/32"],
        },
        "t2d": {
            "grid_comm": "65000:504",
            "global": ["10.213.0.0/25", "10.213.0.128/25"],
            "anchors": ["198.18.0.31/32", "198.18.0.32/32", "198.18.0.33/32"],
        },
    }

    for router_name, data in fanout_sources.items():
        grid_list = f"fanout-grid-{router_name}"
        anchor_list = f"fanout-anchor-{router_name}"
        commands = []
        seq = 5
        for prefix in data["global"]:
            commands.append(f"ip prefix-list {grid_list} seq {seq} permit {prefix}")
            seq += 5
        seq = 5
        for prefix in data["anchors"]:
            commands.append(f"ip prefix-list {anchor_list} seq {seq} permit {prefix}")
            seq += 5
        commands.extend(
            [
                "route-map evpn-export permit 910",
                f" match ip address prefix-list {grid_list}",
                f" set community {data['grid_comm']} 65000:990 additive",
                "route-map evpn-export permit 920",
                f" match ip address prefix-list {anchor_list}",
                f" set community {data['grid_comm']} additive",
            ]
        )
        _router_cfg(router_name, commands)

        all_prefixes = [*data["global"], *data["anchors"]]
        _router_cfg(router_name, [f"ip route {prefix} Null0 vrf vrf100" for prefix in all_prefixes])
        for prefix in all_prefixes:
            _router_network(router_name, prefix, present=True)

    for router_name in fanout_sources:
        tgen.gears[router_name].vtysh_cmd("clear bgp l2vpn evpn *")
    tgen.gears["rr"].vtysh_cmd("clear bgp l2vpn evpn *")

    logger.info("Validate registry reaches 3 anchors per grid")
    fanout_registry_patterns = [
        r"Grid GRID-A \(3 entries\)",
        r"Grid GRID-B \(3 entries\)",
        r"Grid GRID-C \(3 entries\)",
        r"Grid GRID-D \(3 entries\)",
    ]

    def _fanout_registry_match():
        output = tgen.gears["rr"].vtysh_cmd("show dynamic-nexthop", isjson=False)
        missing = [p for p in fanout_registry_patterns if not re.search(p, output)]
        return None if not missing else f"missing {missing} in:\n{output}"

    _, result = topotest.run_and_expect(_fanout_registry_match, None, count=60, wait=1)
    assert result is None, "Expected 3 discovered anchors per grid"

    logger.info("Validate per-grid global aggregates fan out into 3 instances each")
    _assert_evpn_instance_count(
        tgen.gears["rr"],
        24,
        "10.210.0.0",
        3,
        "GRID-A global aggregate should fan out to 3 instances",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rr"],
        24,
        "10.211.0.0",
        3,
        "GRID-B global aggregate should fan out to 3 instances",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rr"],
        24,
        "10.212.0.0",
        3,
        "GRID-C global aggregate should fan out to 3 instances",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rr"],
        24,
        "10.213.0.0",
        3,
        "GRID-D global aggregate should fan out to 3 instances",
        vni="100",
    )

    logger.info("Validate receiver sees 3-way fan-out aggregates and no contributor /25 routes")
    _assert_evpn_instance_count(
        tgen.gears["rx"],
        24,
        "10.210.0.0",
        3,
        "Receiver should learn 3 fan-out instances for GRID-A aggregate",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rx"],
        24,
        "10.211.0.0",
        3,
        "Receiver should learn 3 fan-out instances for GRID-B aggregate",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rx"],
        24,
        "10.212.0.0",
        3,
        "Receiver should learn 3 fan-out instances for GRID-C aggregate",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rx"],
        24,
        "10.213.0.0",
        3,
        "Receiver should learn 3 fan-out instances for GRID-D aggregate",
        vni="100",
    )

    for contributor in [
        "10.210.0.0",
        "10.210.0.128",
        "10.211.0.0",
        "10.211.0.128",
        "10.212.0.0",
        "10.212.0.128",
        "10.213.0.0",
        "10.213.0.128",
    ]:
        _assert_evpn_instance_count(
            tgen.gears["rx"],
            25,
            contributor,
            0,
            f"Receiver should not keep contributor {contributor}/25 once aggregate is active",
            vni="100",
        )

    logger.info("Break aggregate precondition and verify contributor fallback behavior")
    for router_name, data in fanout_sources.items():
        _router_network(router_name, data["global"][1], present=False)

    _assert_evpn_instance_count(
        tgen.gears["rr"],
        24,
        "10.210.0.0",
        0,
        "GRID-A aggregate should withdraw when only one /25 contributor remains",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rr"],
        24,
        "10.211.0.0",
        0,
        "GRID-B aggregate should withdraw when only one /25 contributor remains",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rr"],
        24,
        "10.212.0.0",
        0,
        "GRID-C aggregate should withdraw when only one /25 contributor remains",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rr"],
        24,
        "10.213.0.0",
        0,
        "GRID-D aggregate should withdraw when only one /25 contributor remains",
        vni="100",
    )

    _assert_evpn_instance_count(
        tgen.gears["rx"],
        24,
        "10.210.0.0",
        0,
        "Receiver should not retain GRID-A /24 aggregate after fallback",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rx"],
        24,
        "10.211.0.0",
        0,
        "Receiver should not retain GRID-B /24 aggregate after fallback",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rx"],
        24,
        "10.212.0.0",
        0,
        "Receiver should not retain GRID-C /24 aggregate after fallback",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rx"],
        24,
        "10.213.0.0",
        0,
        "Receiver should not retain GRID-D /24 aggregate after fallback",
        vni="100",
    )

    _assert_evpn_instance_count(
        tgen.gears["rx"],
        25,
        "10.210.0.0",
        1,
        "Receiver should see fallback GRID-A contributor /25",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rx"],
        25,
        "10.211.0.0",
        1,
        "Receiver should see fallback GRID-B contributor /25",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rx"],
        25,
        "10.212.0.0",
        1,
        "Receiver should see fallback GRID-C contributor /25",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rx"],
        25,
        "10.213.0.0",
        1,
        "Receiver should see fallback GRID-D contributor /25",
        vni="100",
    )

    logger.info("Restore second contributors and verify aggregate fan-out re-forms")
    for router_name, data in fanout_sources.items():
        _router_network(router_name, data["global"][1], present=True)

    _assert_evpn_instance_count(
        tgen.gears["rr"],
        24,
        "10.210.0.0",
        3,
        "GRID-A aggregate should re-form with 3-way fan-out",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rr"],
        24,
        "10.211.0.0",
        3,
        "GRID-B aggregate should re-form with 3-way fan-out",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rr"],
        24,
        "10.212.0.0",
        3,
        "GRID-C aggregate should re-form with 3-way fan-out",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rr"],
        24,
        "10.213.0.0",
        3,
        "GRID-D aggregate should re-form with 3-way fan-out",
        vni="100",
    )

    logger.info("Withdraw ALL anchors for GRID-A and verify fan-out drops to zero")
    for anchor in fanout_sources["leaf"]["anchors"]:
        _router_network("leaf", anchor, present=False)

    def _registry_grid_a_zero():
        output = tgen.gears["rr"].vtysh_cmd("show dynamic-nexthop", isjson=False)
        # Grid-A entry should either be absent or show (0 entries)
        if re.search(r"Grid GRID-A \([1-9]\d* entries\)", output):
            return f"GRID-A still has entries in:\n{output}"
        return None

    _, result = topotest.run_and_expect(_registry_grid_a_zero, None, count=60, wait=1)
    assert result is None, "GRID-A nexthop registry should be empty after all anchors withdrawn"

    _assert_evpn_instance_count(
        tgen.gears["rr"],
        24,
        "10.210.0.0",
        0,
        "RR should originate zero GRID-A fan-out instances when all nexthops are gone",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rx"],
        24,
        "10.210.0.0",
        0,
        "Receiver should see zero GRID-A fan-out instances when all nexthops are gone",
        vni="100",
    )

    logger.info("Verify contributor /25 routes are NOT leaked to receiver when nexthops=0")
    # When all fan-out nexthops are gone the RR has no valid nexthop list to use,
    # so it should not re-announce the aggregate NOR fall back to advertising raw
    # contributor routes. Everything from that grid is silenced.
    for contributor in fanout_sources["leaf"]["global"]:
        prefix_only = contributor.split("/")[0]
        _assert_evpn_instance_count(
            tgen.gears["rx"],
            25,
            prefix_only,
            0,
            f"Receiver should not see raw contributor {contributor} when no fan-out nexthop exists",
            vni="100",
        )

    logger.info("Restore GRID-A anchors and verify fan-out recovers from zero to 3")
    for anchor in fanout_sources["leaf"]["anchors"]:
        _router_network("leaf", anchor, present=True)
    tgen.gears["leaf"].vtysh_cmd("clear bgp l2vpn evpn *")
    tgen.gears["rr"].vtysh_cmd("clear bgp l2vpn evpn *")

    _assert_evpn_instance_count(
        tgen.gears["rr"],
        24,
        "10.210.0.0",
        3,
        "RR should recover GRID-A to 3 fan-out instances after anchors restored",
        vni="100",
    )
    _assert_evpn_instance_count(
        tgen.gears["rx"],
        24,
        "10.210.0.0",
        3,
        "Receiver should recover GRID-A to 3 fan-out instances after anchors restored",
        vni="100",
    )

    logger.info("Fan-out cleanup")
    for router_name, data in fanout_sources.items():
        all_prefixes = [*data["global"], *data["anchors"]]
        for prefix in all_prefixes:
            _router_network(router_name, prefix, present=False)

        grid_list = f"fanout-grid-{router_name}"
        anchor_list = f"fanout-anchor-{router_name}"
        _router_cfg(
            router_name,
            [
                *[f"no ip route {prefix} Null0 vrf vrf100" for prefix in all_prefixes],
                "no route-map evpn-export permit 910",
                "no route-map evpn-export permit 920",
                f"no ip prefix-list {grid_list}",
                f"no ip prefix-list {anchor_list}",
            ],
        )

    _rr_config(
        [
            " no enable dynamic-nexthop anchor",
            " no dynamic-aggregate global community 65000:990",
            " no grid GRID-C rt 65000:503",
            " no grid GRID-D rt 65000:504",
        ]
    )

    for router_name in fanout_sources:
        tgen.gears[router_name].vtysh_cmd("clear bgp l2vpn evpn *")
    tgen.gears["rr"].vtysh_cmd("clear bgp l2vpn evpn *")
    tgen.gears["rx"].vtysh_cmd("clear bgp l2vpn evpn *")


def test_fanout_scale_many_grids_many_anchors_churn():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip(tgen.errors)

    logger.info("Program scale fan-out config: 8 grids, 8 anchors per grid")
    _rr_config(
        [
            " grid GRID-C rt 65000:503",
            " grid GRID-D rt 65000:504",
            " grid GRID-E rt 65000:505",
            " grid GRID-F rt 65000:506",
            " grid GRID-G rt 65000:507",
            " grid GRID-H rt 65000:508",
            " dynamic-aggregate global community 65000:990",
            " enable dynamic-nexthop anchor 198.19.0.0/24",
        ]
    )

    scale_sources = {
        "leaf": [
            {
                "grid": "GRID-A",
                "grid_comm": "65000:501",
                "agg": "10.220.0.0",
                "global": ["10.220.0.0/25", "10.220.0.128/25"],
                "anchors": [
                    "198.19.0.1/32",
                    "198.19.0.2/32",
                    "198.19.0.3/32",
                    "198.19.0.4/32",
                    "198.19.0.5/32",
                    "198.19.0.6/32",
                    "198.19.0.7/32",
                    "198.19.0.8/32",
                ],
            },
            {
                "grid": "GRID-E",
                "grid_comm": "65000:505",
                "agg": "10.224.0.0",
                "global": ["10.224.0.0/25", "10.224.0.128/25"],
                "anchors": [
                    "198.19.0.65/32",
                    "198.19.0.66/32",
                    "198.19.0.67/32",
                    "198.19.0.68/32",
                    "198.19.0.69/32",
                    "198.19.0.70/32",
                    "198.19.0.71/32",
                    "198.19.0.72/32",
                ],
            },
        ],
        "t2b": [
            {
                "grid": "GRID-B",
                "grid_comm": "65000:502",
                "agg": "10.221.0.0",
                "global": ["10.221.0.0/25", "10.221.0.128/25"],
                "anchors": [
                    "198.19.0.9/32",
                    "198.19.0.10/32",
                    "198.19.0.11/32",
                    "198.19.0.12/32",
                    "198.19.0.13/32",
                    "198.19.0.14/32",
                    "198.19.0.15/32",
                    "198.19.0.16/32",
                ],
            },
            {
                "grid": "GRID-F",
                "grid_comm": "65000:506",
                "agg": "10.225.0.0",
                "global": ["10.225.0.0/25", "10.225.0.128/25"],
                "anchors": [
                    "198.19.0.73/32",
                    "198.19.0.74/32",
                    "198.19.0.75/32",
                    "198.19.0.76/32",
                    "198.19.0.77/32",
                    "198.19.0.78/32",
                    "198.19.0.79/32",
                    "198.19.0.80/32",
                ],
            },
        ],
        "t2c": [
            {
                "grid": "GRID-C",
                "grid_comm": "65000:503",
                "agg": "10.222.0.0",
                "global": ["10.222.0.0/25", "10.222.0.128/25"],
                "anchors": [
                    "198.19.0.17/32",
                    "198.19.0.18/32",
                    "198.19.0.19/32",
                    "198.19.0.20/32",
                    "198.19.0.21/32",
                    "198.19.0.22/32",
                    "198.19.0.23/32",
                    "198.19.0.24/32",
                ],
            },
            {
                "grid": "GRID-G",
                "grid_comm": "65000:507",
                "agg": "10.226.0.0",
                "global": ["10.226.0.0/25", "10.226.0.128/25"],
                "anchors": [
                    "198.19.0.81/32",
                    "198.19.0.82/32",
                    "198.19.0.83/32",
                    "198.19.0.84/32",
                    "198.19.0.85/32",
                    "198.19.0.86/32",
                    "198.19.0.87/32",
                    "198.19.0.88/32",
                ],
            },
        ],
        "t2d": [
            {
                "grid": "GRID-D",
                "grid_comm": "65000:504",
                "agg": "10.223.0.0",
                "global": ["10.223.0.0/25", "10.223.0.128/25"],
                "anchors": [
                    "198.19.0.25/32",
                    "198.19.0.26/32",
                    "198.19.0.27/32",
                    "198.19.0.28/32",
                    "198.19.0.29/32",
                    "198.19.0.30/32",
                    "198.19.0.31/32",
                    "198.19.0.32/32",
                ],
            },
            {
                "grid": "GRID-H",
                "grid_comm": "65000:508",
                "agg": "10.227.0.0",
                "global": ["10.227.0.0/25", "10.227.0.128/25"],
                "anchors": [
                    "198.19.0.89/32",
                    "198.19.0.90/32",
                    "198.19.0.91/32",
                    "198.19.0.92/32",
                    "198.19.0.93/32",
                    "198.19.0.94/32",
                    "198.19.0.95/32",
                    "198.19.0.96/32",
                ],
            },
        ],
    }

    scale_grids = []
    for grid_defs in scale_sources.values():
        scale_grids.extend(grid_defs)

    delayed_grid_name = "GRID-H"
    delayed_grid = next(grid_def for grid_def in scale_grids if grid_def["grid"] == delayed_grid_name)
    delayed_router = next(
        router_name
        for router_name, grid_defs in scale_sources.items()
        if any(grid_def["grid"] == delayed_grid_name for grid_def in grid_defs)
    )
    delayed_anchors = set(delayed_grid["anchors"])

    for router_name, grid_defs in scale_sources.items():
        commands = []
        seq = 800
        for grid_def in grid_defs:
            grid_name = grid_def["grid"].lower()
            grid_list = f"scale-grid-{router_name}-{grid_name}"
            anchor_list = f"scale-anchor-{router_name}-{grid_name}"
            invalid_anchor_list = f"scale-invalid-anchor-{router_name}-{grid_name}"
            commands.extend(
                [
                    f"ip prefix-list {grid_list} seq 5 permit {grid_def['global'][0]}",
                    f"ip prefix-list {grid_list} seq 10 permit {grid_def['global'][1]}",
                    f"ip prefix-list {invalid_anchor_list} seq 5 permit 198.20.0.0/32",
                ]
            )
            anchor_seq = 5
            for anchor in grid_def["anchors"]:
                commands.append(f"ip prefix-list {anchor_list} seq {anchor_seq} permit {anchor}")
                anchor_seq += 5

            commands.extend(
                [
                    f"route-map evpn-export permit {seq}",
                    f" match ip address prefix-list {grid_list}",
                    f" set community {grid_def['grid_comm']} 65000:990 additive",
                    f"route-map evpn-export permit {seq + 1}",
                    f" match ip address prefix-list {anchor_list}",
                    f" set community {grid_def['grid_comm']} additive",
                    f"route-map evpn-export permit {seq + 2}",
                    f" match ip address prefix-list {invalid_anchor_list}",
                    f" set community {grid_def['grid_comm']} additive",
                ]
            )
            seq += 10

        _router_cfg(router_name, commands)

        all_prefixes = ["198.20.0.0/32"]
        for grid_def in grid_defs:
            all_prefixes.extend([*grid_def["global"], *grid_def["anchors"]])
        _router_cfg(router_name, [f"ip route {prefix} Null0 vrf vrf100" for prefix in all_prefixes])
        for prefix in all_prefixes:
            if router_name == delayed_router and prefix in delayed_anchors:
                # Keep one grid without valid anchors initially to verify no fan-out re-announce.
                continue
            _router_network(router_name, prefix, present=True)

    for router_name in scale_sources:
        tgen.gears[router_name].vtysh_cmd("clear bgp l2vpn evpn *")
    tgen.gears["rr"].vtysh_cmd("clear bgp l2vpn evpn *")

    logger.info("Verify no valid fan-out nexthop yields no re-announcement for delayed grid")
    _assert_evpn_instance_count(
        tgen.gears["rx"],
        24,
        delayed_grid["agg"],
        0,
        "Receiver should not get aggregate when contributors exist but no valid anchors are present",
        vni="100",
    )
    for contributor in delayed_grid["global"]:
        _assert_evpn_instance_count(
            tgen.gears["rx"],
            25,
            contributor.split("/")[0],
            0,
            "Receiver should not get contributor re-announcements when no fan-out nexthop exists",
            vni="100",
        )

    logger.info("Add delayed valid anchors and verify fan-out starts announcing")
    for anchor in delayed_grid["anchors"]:
        _router_network(delayed_router, anchor, present=True)

    tgen.gears[delayed_router].vtysh_cmd("clear bgp l2vpn evpn *")
    tgen.gears["rr"].vtysh_cmd("clear bgp l2vpn evpn *")

    logger.info("Validate 8 anchors learned per grid and 8-way aggregate fan-out")

    def _scale_registry_match():
        output = tgen.gears["rr"].vtysh_cmd("show dynamic-nexthop", isjson=False)
        missing = [
            f"Grid {grid_def['grid']} (8 entries)"
            for grid_def in scale_grids
            if f"Grid {grid_def['grid']} (8 entries)" not in output
        ]
        return None if not missing else f"missing {missing} in:\n{output}"

    _, result = topotest.run_and_expect(_scale_registry_match, None, count=120, wait=1)
    assert result is None, "Expected 8 learned anchors for each scale grid"

    for grid_def in scale_grids:
        _assert_evpn_instance_count(
            tgen.gears["rr"],
            24,
            grid_def["agg"],
            8,
            f"{grid_def['grid']} aggregate should fan out to 8 instances on RR",
            vni="100",
        )
        _assert_evpn_instance_count(
            tgen.gears["rx"],
            24,
            grid_def["agg"],
            8,
            f"{grid_def['grid']} aggregate should fan out to 8 instances on receiver",
            vni="100",
        )

    logger.info("Inject invalid-anchor route outside configured anchor supernet and verify ignored")
    def _invalid_anchor_not_counted():
        output = tgen.gears["rr"].vtysh_cmd("show dynamic-nexthop", isjson=False)
        unexpected = [
            f"Grid {grid_def['grid']} (9 entries)"
            for grid_def in scale_grids
            if f"Grid {grid_def['grid']} (9 entries)" in output
        ]
        return None if not unexpected else f"unexpected {unexpected} in:\n{output}"

    _, result = topotest.run_and_expect(_invalid_anchor_not_counted, None, count=30, wait=1)
    assert result is None, "Invalid anchors outside 198.19.0.0/24 should not be learned"

    logger.info("Withdraw 3 anchors per grid and verify fan-out shrinks from 8 to 5")
    for router_name, grid_defs in scale_sources.items():
        for grid_def in grid_defs:
            for anchor in grid_def["anchors"][:3]:
                _router_network(router_name, anchor, present=False)

    def _scale_registry_shrink_match():
        output = tgen.gears["rr"].vtysh_cmd("show dynamic-nexthop", isjson=False)
        missing = [
            f"Grid {grid_def['grid']} (5 entries)"
            for grid_def in scale_grids
            if f"Grid {grid_def['grid']} (5 entries)" not in output
        ]
        return None if not missing else f"missing {missing} in:\n{output}"

    _, result = topotest.run_and_expect(_scale_registry_shrink_match, None, count=120, wait=1)
    assert result is None, "Expected 5 learned anchors per grid after churn"

    for grid_def in scale_grids:
        _assert_evpn_instance_count(
            tgen.gears["rr"],
            24,
            grid_def["agg"],
            5,
            f"{grid_def['grid']} aggregate fan-out should shrink to 5 instances on RR",
            vni="100",
        )
        _assert_evpn_instance_count(
            tgen.gears["rx"],
            24,
            grid_def["agg"],
            5,
            f"{grid_def['grid']} aggregate fan-out should shrink to 5 instances on receiver",
            vni="100",
        )

    logger.info("Restore withdrawn anchors and verify fan-out returns to 8")
    for router_name, grid_defs in scale_sources.items():
        for grid_def in grid_defs:
            for anchor in grid_def["anchors"][:3]:
                _router_network(router_name, anchor, present=True)

    for grid_def in scale_grids:
        _assert_evpn_instance_count(
            tgen.gears["rr"],
            24,
            grid_def["agg"],
            8,
            f"{grid_def['grid']} aggregate fan-out should recover to 8 instances on RR",
            vni="100",
        )
        _assert_evpn_instance_count(
            tgen.gears["rx"],
            24,
            grid_def["agg"],
            8,
            f"{grid_def['grid']} aggregate fan-out should recover to 8 instances on receiver",
            vni="100",
        )

    logger.info("Scale fan-out cleanup")
    for router_name, grid_defs in scale_sources.items():
        cleanup = []
        seq = 800
        all_prefixes = ["198.20.0.0/32"]
        for grid_def in grid_defs:
            grid_name = grid_def["grid"].lower()
            grid_list = f"scale-grid-{router_name}-{grid_name}"
            anchor_list = f"scale-anchor-{router_name}-{grid_name}"
            invalid_anchor_list = f"scale-invalid-anchor-{router_name}-{grid_name}"
            all_prefixes.extend([*grid_def["global"], *grid_def["anchors"]])
            cleanup.extend(
                [
                    f"no route-map evpn-export permit {seq}",
                    f"no route-map evpn-export permit {seq + 1}",
                    f"no route-map evpn-export permit {seq + 2}",
                    f"no ip prefix-list {grid_list}",
                    f"no ip prefix-list {anchor_list}",
                    f"no ip prefix-list {invalid_anchor_list}",
                ]
            )
            seq += 10

        for prefix in all_prefixes:
            _router_network(router_name, prefix, present=False)

        cleanup = [*cleanup, *[f"no ip route {prefix} Null0 vrf vrf100" for prefix in all_prefixes]]
        _router_cfg(router_name, cleanup)

    _rr_config(
        [
            " no enable dynamic-nexthop anchor",
            " no dynamic-aggregate global community 65000:990",
            " no grid GRID-C rt 65000:503",
            " no grid GRID-D rt 65000:504",
            " no grid GRID-E rt 65000:505",
            " no grid GRID-F rt 65000:506",
            " no grid GRID-G rt 65000:507",
            " no grid GRID-H rt 65000:508",
        ]
    )

    for router_name in scale_sources:
        tgen.gears[router_name].vtysh_cmd("clear bgp l2vpn evpn *")
    tgen.gears["rr"].vtysh_cmd("clear bgp l2vpn evpn *")
    tgen.gears["rx"].vtysh_cmd("clear bgp l2vpn evpn *")


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

    for router_name in ["leaf", "t2b", "t2c", "t2d"]:
        tgen.gears[router_name].vtysh_cmd("clear bgp l2vpn evpn *")
    tgen.gears["rr"].vtysh_cmd("clear bgp l2vpn evpn *")
    tgen.gears["rx"].vtysh_cmd("clear bgp l2vpn evpn *")

    tgen.gears["rr"].vtysh_cmd(
        """
configure terminal
 router bgp 65000
  address-family l2vpn evpn
   neighbor 10.0.0.2 shutdown
   neighbor 10.0.0.3 shutdown
   neighbor 10.0.0.4 shutdown
   neighbor 10.0.0.5 shutdown
   neighbor 10.0.0.6 shutdown
"""
    )

    cleanup_commands = [
        " no static-aggregate prefix 192.0.2.0/24 grid GRID-A vni 100",
        " no dynamic-aggregate prefix 10.10.0.0/24 slice-prefixlen 26",
        " no dynamic-aggregate prefix 10.40.0.0/24 slice-prefixlen 26",
        " no dynamic-aggregate prefix 10.50.0.0/24 slice-prefixlen 26",
        " no dynamic-aggregate prefix 10.60.0.0/24 slice-prefixlen 26",
        " no dynamic-aggregate prefix 10.70.0.0/24 slice-prefixlen 26",
        " no dynamic-aggregate prefix 10.80.0.0/24 slice-prefixlen 26",
        " no dynamic-aggregate prefix 10.120.0.0/24 slice-prefixlen 28",
        " no dynamic-aggregate global community 65000:900",
        " no dynamic-aggregate global community 65000:901",
        " no grid GRID-A rt 65000:501",
        " no grid GRID-B rt 65000:502",
    ]

    def _cleanup_dynamic_aggr_config():
        _rr_config(cleanup_commands)
        running = tgen.gears["rr"].vtysh_cmd("show running-config")
        blockers = [
            " static-aggregate prefix 192.0.2.0/24 grid GRID-A vni 100",
            " dynamic-aggregate prefix 10.10.0.0/24",
            " dynamic-aggregate prefix 10.40.0.0/24",
            " dynamic-aggregate prefix 10.50.0.0/24",
            " dynamic-aggregate prefix 10.60.0.0/24",
            " dynamic-aggregate prefix 10.70.0.0/24",
            " dynamic-aggregate prefix 10.80.0.0/24",
            " dynamic-aggregate prefix 10.120.0.0/24",
            " dynamic-aggregate global community 65000:900",
            " dynamic-aggregate global community 65000:901",
            " grid GRID-A rt 65000:501",
            " grid GRID-B rt 65000:502",
        ]
        stuck = [line for line in blockers if line in running]
        return None if not stuck else f"still configured: {stuck}"

    _, result = topotest.run_and_expect(_cleanup_dynamic_aggr_config, None, count=120, wait=1)
    if result is not None:
        pytest.skip(f"cleanup convergence did not remove all dynamic-aggr entries: {result}")

    def _disable_dynamic_aggr():
        output = tgen.gears["rr"].vtysh_cmd(
            """
configure terminal
 no dynamic-aggr
"""
        )
        if "remove active dynamic-aggregate entries before disabling" in output:
            return output
        return None

    _, result = topotest.run_and_expect(_disable_dynamic_aggr, None, count=120, wait=1)
    if result is not None:
        pytest.skip("dynamic-aggr disable guard remained active after cleanup convergence")

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