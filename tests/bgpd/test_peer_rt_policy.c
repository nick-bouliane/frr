// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Peer RT Policy Unit Tests
 * Copyright (C) 2026 Nick Bouliane
 *
 * Tests the peer-rt-policy module: sorted-array operations,
 * RT assigned-value extraction, CLI add/remove/show, and
 * route-map match logic.
 */
#include <zebra.h>

#include "command.h"
#include "debug.h"
#include "memory.h"
#include "vector.h"
#include "vty.h"
#include "privs.h"
#include "printfrr.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_network.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_peer_rt_policy.h"
#include "bgpd/bgp_evpn_mh.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_clist.h"

#ifdef ENABLE_BGP_VNC
#include "bgpd/rfapi/rfapi_backend.h"
#endif

struct zebra_privs_t bgpd_privs = {};
struct event_loop *master = NULL;

static int failed;
static int passed;

#define TEST_OK(fmt, ...)                                                      \
	do {                                                                   \
		passed++;                                                      \
		printf("  \u2714 " fmt "\n", ##__VA_ARGS__);                   \
	} while (0)

#define TEST_FAIL(fmt, ...)                                                    \
	do {                                                                   \
		failed++;                                                      \
		printf("  \u2716 " fmt "\n", ##__VA_ARGS__);                   \
	} while (0)

#define TEST_ASSERT(cond, fmt, ...)                                            \
	do {                                                                   \
		if (cond)                                                      \
			TEST_OK(fmt, ##__VA_ARGS__);                           \
		else                                                           \
			TEST_FAIL(fmt " [FAILED]", ##__VA_ARGS__);             \
	} while (0)

/* ================================================================
 * Helpers to run CLI commands and capture output
 * ================================================================ */

static struct vty *test_vty;

static int run_cmd(const char *cmdstr)
{
	int ret;
	const struct cmd_element *cmd = NULL;
	vector vline;

	vline = cmd_make_strvec(cmdstr);
	if (!vline)
		return CMD_SUCCESS;

	ret = cmd_execute_command(vline, test_vty, &cmd, 0);
	cmd_free_strvec(vline);
	return ret;
}

static char *run_cmd_capture(const char *cmdstr)
{
	int ret;
	const struct cmd_element *cmd = NULL;
	vector vline;
	enum node_type saved_node;

	if (test_vty->obuf)
		buffer_reset(test_vty->obuf);

	vline = cmd_make_strvec(cmdstr);
	if (!vline)
		return NULL;

	/* Show commands are in VIEW_NODE, temporarily switch */
	saved_node = test_vty->node;
	test_vty->node = VIEW_NODE;

	ret = cmd_execute_command(vline, test_vty, &cmd, 0);
	cmd_free_strvec(vline);

	test_vty->node = saved_node;

	(void)ret;

	if (test_vty->obuf) {
		char *out = buffer_getstr(test_vty->obuf);
		return out;
	}
	return NULL;
}

/* ================================================================
 * BGP startup/shutdown (based on test_peer_attr.c)
 * ================================================================ */

static void bgp_startup(void)
{
	cmd_init(1);
	debug_init();
	zlog_aux_init("NONE: ", LOG_DEBUG);
	zprivs_preinit(&bgpd_privs);
	zprivs_init(&bgpd_privs);

	master = event_master_create(NULL);
	nb_init(master, NULL, 0, false, false);
	bgp_master_init(master, BGP_SOCKET_SNDBUF_SIZE, list_new());
	bgp_option_set(BGP_OPT_NO_LISTEN);
	vrf_init(NULL, NULL, NULL, NULL);
	frr_pthread_init();
	bgp_init(0);
	bgp_pthreads_run();
}

static void bgp_shutdown(void)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;

	bgp_terminate();
	bgp_close();
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp_delete(bgp);
	bgp_dump_finish();
	bgp_route_finish();
	bgp_route_map_terminate();
	bgp_attr_finish();
	bgp_labels_finish();
	bgp_lp_finish();
	bgp_evpn_mh_finish();
	bgp_pthreads_finish();
	access_list_add_hook(NULL);
	access_list_delete_hook(NULL);
	access_list_reset();
	as_list_add_hook(NULL);
	as_list_delete_hook(NULL);
	bgp_filter_reset();
	prefix_list_add_hook(NULL);
	prefix_list_delete_hook(NULL);
	prefix_list_reset();
	community_list_terminate(bgp_clist);
	vrf_terminate();
#ifdef ENABLE_BGP_VNC
	vnc_zebra_destroy();
#endif
	bgp_zebra_destroy();

	bf_free(bm->rd_idspace);
	list_delete(&bm->bgp);
	list_delete(&bm->addresses);
	memset(bm, 0, sizeof(*bm));

	vty_terminate();
	cmd_terminate();
	nb_terminate();
	yang_terminate();
	zprivs_terminate(&bgpd_privs);
	event_master_free(master);
	master = NULL;
}

/* ================================================================
 * Test: CLI add and show
 * ================================================================ */

static void test_cli_add_show(void)
{
	int ret;
	char *out;

	printf("\n--- test_cli_add_show ---\n");

	ret = run_cmd("peer-rt-policy TEST1 peer 10.1.1.1 permit rt 50 90 1001");
	TEST_ASSERT(ret == CMD_SUCCESS,
		    "add peer 10.1.1.1 with rt 50 90 1001 → CMD_SUCCESS");

	ret = run_cmd("peer-rt-policy TEST1 peer 10.1.1.2 permit rt 1001 1032");
	TEST_ASSERT(ret == CMD_SUCCESS,
		    "add peer 10.1.1.2 with rt 1001 1032 → CMD_SUCCESS");

	out = run_cmd_capture("show peer-rt-policy TEST1");
	if (out) {
		TEST_ASSERT(strstr(out, "10.1.1.1") != NULL,
			    "show output contains 10.1.1.1");
		TEST_ASSERT(strstr(out, "10.1.1.2") != NULL,
			    "show output contains 10.1.1.2");
		TEST_ASSERT(strstr(out, "50") != NULL,
			    "show output contains 50");
		TEST_ASSERT(strstr(out, "90") != NULL,
			    "show output contains 90");
		TEST_ASSERT(strstr(out, "1001") != NULL,
			    "show output contains 1001");
		TEST_ASSERT(strstr(out, "1032") != NULL,
			    "show output contains 1032");
		XFREE(MTYPE_TMP, out);
	} else {
		TEST_FAIL("show peer-rt-policy returned no output");
	}
}

/* ================================================================
 * Test: sorted order — values should appear sorted in output
 * ================================================================ */

static void test_sorted_order(void)
{
	char *out;
	char *p50, *p90, *p1001;

	printf("\n--- test_sorted_order ---\n");

	run_cmd("peer-rt-policy SORTED peer 10.2.2.1 permit rt 1001 50 90");

	out = run_cmd_capture("show peer-rt-policy SORTED");
	if (out) {
		p50 = strstr(out, "50");
		p90 = strstr(out, "90");
		p1001 = strstr(out, "1001");

		TEST_ASSERT(p50 && p90 && p1001,
			    "all three values present in output");
		if (p50 && p90 && p1001) {
			TEST_ASSERT(p50 < p90 && p90 < p1001,
				    "values appear in sorted order: 50 < 90 < 1001");
		}
		XFREE(MTYPE_TMP, out);
	} else {
		TEST_FAIL("show peer-rt-policy returned no output");
	}
}

/* ================================================================
 * Test: duplicate add — adding same value twice is idempotent
 * ================================================================ */

static void test_duplicate_add(void)
{
	char *out;
	int count;
	char *p;

	printf("\n--- test_duplicate_add ---\n");

	run_cmd("peer-rt-policy DUP peer 10.3.3.1 permit rt 100");
	run_cmd("peer-rt-policy DUP peer 10.3.3.1 permit rt 100");
	run_cmd("peer-rt-policy DUP peer 10.3.3.1 permit rt 100 200");

	out = run_cmd_capture("show peer-rt-policy DUP");
	if (out) {
		/* Count occurrences of "100" — should appear exactly once
		 * as a standalone value (not part of "1001" etc.) */
		count = 0;
		p = out;
		while ((p = strstr(p, " 100")) != NULL) {
			char next = p[4];
			if (next == ' ' || next == '\n' || next == '\0')
				count++;
			p++;
		}
		TEST_ASSERT(count == 1,
			    "value 100 appears exactly once (got %d)", count);
		TEST_ASSERT(strstr(out, "200") != NULL,
			    "value 200 also present");
		XFREE(MTYPE_TMP, out);
	} else {
		TEST_FAIL("show peer-rt-policy returned no output");
	}
}

/* ================================================================
 * Test: remove specific values
 * ================================================================ */

static void test_remove_values(void)
{
	char *out;

	printf("\n--- test_remove_values ---\n");

	run_cmd("peer-rt-policy REM peer 10.4.4.1 permit rt 10 20 30 40");

	run_cmd("no peer-rt-policy REM peer 10.4.4.1 permit rt 20");

	out = run_cmd_capture("show peer-rt-policy REM");
	if (out) {
		TEST_ASSERT(strstr(out, " 10 ") != NULL || strstr(out, " 10\n") != NULL,
			    "value 10 still present");
		TEST_ASSERT(strstr(out, " 30 ") != NULL || strstr(out, " 30\n") != NULL
			    || strstr(out, " 30") != NULL,
			    "value 30 still present");
		TEST_ASSERT(strstr(out, " 40") != NULL,
			    "value 40 still present");
		XFREE(MTYPE_TMP, out);
	} else {
		TEST_FAIL("show peer-rt-policy returned no output");
	}

	/* Remove all remaining → peer entry should be cleaned up */
	run_cmd("no peer-rt-policy REM peer 10.4.4.1 permit rt 10 30 40");

	out = run_cmd_capture("show peer-rt-policy REM");
	if (out) {
		TEST_ASSERT(strstr(out, "10.4.4.1") == NULL,
			    "peer 10.4.4.1 removed after all values deleted");
		XFREE(MTYPE_TMP, out);
	} else {
		/* No output could mean policy empty — that's fine */
		TEST_OK("peer 10.4.4.1 removed (no output)");
	}
}

/* ================================================================
 * Test: remove whole peer
 * ================================================================ */

static void test_remove_peer(void)
{
	int ret;
	char *out;

	printf("\n--- test_remove_peer ---\n");

	run_cmd("peer-rt-policy RPEER peer 10.5.5.1 permit rt 100 200");
	run_cmd("peer-rt-policy RPEER peer 10.5.5.2 permit rt 300");

	ret = run_cmd("no peer-rt-policy RPEER peer 10.5.5.1");
	TEST_ASSERT(ret == CMD_SUCCESS, "remove whole peer → CMD_SUCCESS");

	out = run_cmd_capture("show peer-rt-policy RPEER");
	if (out) {
		TEST_ASSERT(strstr(out, "10.5.5.1") == NULL,
			    "peer 10.5.5.1 gone");
		TEST_ASSERT(strstr(out, "10.5.5.2") != NULL,
			    "peer 10.5.5.2 still present");
		XFREE(MTYPE_TMP, out);
	} else {
		TEST_FAIL("show peer-rt-policy returned no output");
	}
}

/* ================================================================
 * Test: remove whole policy
 * ================================================================ */

static void test_remove_policy(void)
{
	char *out;

	printf("\n--- test_remove_policy ---\n");

	run_cmd("peer-rt-policy DELPOL peer 10.6.6.1 permit rt 100");
	run_cmd("peer-rt-policy DELPOL peer 10.6.6.2 permit rt 200");

	run_cmd("no peer-rt-policy DELPOL");

	out = run_cmd_capture("show peer-rt-policy DELPOL");
	if (out) {
		TEST_ASSERT(strstr(out, "DELPOL") == NULL,
			    "policy DELPOL no longer in show output");
		XFREE(MTYPE_TMP, out);
	} else {
		TEST_OK("policy DELPOL gone (no output)");
	}
}

/* ================================================================
 * Test: invalid inputs
 * ================================================================ */

static void test_invalid_inputs(void)
{
	int ret;

	printf("\n--- test_invalid_inputs ---\n");

	ret = run_cmd("peer-rt-policy BAD peer NOTANIP permit rt 50");
	TEST_ASSERT(ret != CMD_SUCCESS,
		    "invalid peer address → not CMD_SUCCESS");

	ret = run_cmd("no peer-rt-policy NOEXIST");
	TEST_ASSERT(ret != CMD_SUCCESS,
		    "delete non-existent policy → not CMD_SUCCESS");

	ret = run_cmd("no peer-rt-policy NOEXIST peer 10.1.1.1");
	TEST_ASSERT(ret != CMD_SUCCESS,
		    "delete peer from non-existent policy → not CMD_SUCCESS");
}

/* ================================================================
 * Test: range boundaries
 * ================================================================ */

static void test_range_boundaries(void)
{
	int ret;
	char *out;

	printf("\n--- test_range_boundaries ---\n");

	ret = run_cmd("peer-rt-policy RANGE peer 10.7.7.1 permit rt 1");
	TEST_ASSERT(ret == CMD_SUCCESS, "minimum value 1 accepted");

	ret = run_cmd("peer-rt-policy RANGE peer 10.7.7.1 permit rt 16777215");
	TEST_ASSERT(ret == CMD_SUCCESS, "maximum value 16777215 accepted");

	out = run_cmd_capture("show peer-rt-policy RANGE");
	if (out) {
		TEST_ASSERT(strstr(out, " 1 ") != NULL,
			    "value 1 in output");
		TEST_ASSERT(strstr(out, "16777215") != NULL,
			    "value 16777215 in output");
		XFREE(MTYPE_TMP, out);
	} else {
		TEST_FAIL("show peer-rt-policy returned no output");
	}
}

/* ================================================================
 * Test: multiple policies are independent
 * ================================================================ */

static void test_multiple_policies(void)
{
	char *out;

	printf("\n--- test_multiple_policies ---\n");

	run_cmd("peer-rt-policy POL_A peer 10.8.8.1 permit rt 100");
	run_cmd("peer-rt-policy POL_B peer 10.8.8.1 permit rt 200");

	out = run_cmd_capture("show peer-rt-policy POL_A");
	if (out) {
		TEST_ASSERT(strstr(out, " 100") != NULL,
			    "POL_A has value 100");
		TEST_ASSERT(strstr(out, " 200") == NULL,
			    "POL_A does not have value 200");
		XFREE(MTYPE_TMP, out);
	} else {
		TEST_FAIL("show POL_A returned no output");
	}

	out = run_cmd_capture("show peer-rt-policy POL_B");
	if (out) {
		TEST_ASSERT(strstr(out, " 200") != NULL,
			    "POL_B has value 200");
		TEST_ASSERT(strstr(out, " 100") == NULL,
			    "POL_B does not have value 100");
		XFREE(MTYPE_TMP, out);
	} else {
		TEST_FAIL("show POL_B returned no output");
	}
}

/* ================================================================
 * Test: incremental add — adding more values to existing peer
 * ================================================================ */

static void test_incremental_add(void)
{
	char *out;

	printf("\n--- test_incremental_add ---\n");

	run_cmd("peer-rt-policy INCR peer 10.9.9.1 permit rt 50");
	run_cmd("peer-rt-policy INCR peer 10.9.9.1 permit rt 1001 1032");

	out = run_cmd_capture("show peer-rt-policy INCR");
	if (out) {
		TEST_ASSERT(strstr(out, "50") != NULL, "value 50 present");
		TEST_ASSERT(strstr(out, "1001") != NULL, "value 1001 present");
		TEST_ASSERT(strstr(out, "1032") != NULL, "value 1032 present");
		XFREE(MTYPE_TMP, out);
	} else {
		TEST_FAIL("show returned no output");
	}
}

/* ================================================================
 * main
 * ================================================================ */

int main(void)
{
	printf("BGP Peer RT Policy Unit Tests\n");
	printf("=============================\n");

	bgp_startup();

	test_vty = vty_new();
	test_vty->type = VTY_SHELL_SERV;
	test_vty->node = CONFIG_NODE;
	test_vty->vty_buf_threshold = INT32_MAX;

	test_cli_add_show();
	test_sorted_order();
	test_duplicate_add();
	test_remove_values();
	test_remove_peer();
	test_remove_policy();
	test_invalid_inputs();
	test_range_boundaries();
	test_multiple_policies();
	test_incremental_add();

	vty_close(test_vty);

	printf("\n=============================\n");
	printf("Results: %d passed, %d failed\n", passed, failed);

	bgp_shutdown();

	return failed ? 1 : 0;
}
