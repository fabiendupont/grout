// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Fabien Dupont

#include <gr_cmocka.h>
#include <gr_event.h>
#include <gr_l2.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_module.h>
#include <gr_vrf.h>

#include <string.h>

int gr_rte_log_type;

// Mock for fdb_stats (defined in l2_stats.c which we don't link here).
struct fdb_stats l2_fdb_stats[L2_MAX_BRIDGES][RTE_MAX_LCORE];

// Mocked functions required by the linker.
void gr_register_api_handler(struct gr_api_handler *) { }
void gr_register_module(struct gr_module *) { }
void iface_type_register(const struct iface_type *) { }
void gr_event_push(uint32_t, const void *) { }
void gr_event_subscribe(struct gr_event_subscription *) { }
uint16_t vrf_default_get_or_create(void) {
	return 0;
}
int vrf_incref(uint16_t) {
	return 0;
}
void fdb_purge_iface(uint16_t) { }
void fdb_purge_bridge(uint16_t) { }
int iface_set_eth_addr(struct iface *iface, const struct rte_ether_addr *mac) {
	(void)iface;
	(void)mac;
	return 0;
}

// Test interface security defaults.
static void test_iface_security_defaults(void **) {
	// New interfaces should have no MAC limit and not be shutdown.
	assert_int_equal(iface_get_max_macs(0), 0);
	assert_false(iface_get_shutdown_on_violation(0));
	assert_false(iface_is_shutdown(0));
	assert_int_equal(iface_get_total_macs(0), 0);
}

// Test interface security bounds checking.
static void test_iface_security_bounds(void **) {
	// Out-of-bounds iface IDs should return safe defaults.
	assert_int_equal(iface_get_max_macs(L2_MAX_IFACES), 0);
	assert_int_equal(iface_get_max_macs(L2_MAX_IFACES + 1), 0);
	assert_false(iface_is_shutdown(L2_MAX_IFACES));
	assert_false(iface_get_shutdown_on_violation(L2_MAX_IFACES));
	assert_int_equal(iface_get_total_macs(L2_MAX_IFACES), 0);
}

// Test MAC limit configuration and enforcement.
static void test_iface_security_mac_limits(void **) {
	uint16_t iface_id = 42;

	memset(&l2_iface_security[iface_id], 0, sizeof(l2_iface_security[0]));
	memset(l2_iface_mac_counts[iface_id], 0, sizeof(l2_iface_mac_counts[0]));

	l2_iface_security[iface_id].max_macs = 5;
	assert_int_equal(iface_get_max_macs(iface_id), 5);

	iface_increment_mac_count(iface_id, 0);
	iface_increment_mac_count(iface_id, 0);
	assert_int_equal(iface_get_total_macs(iface_id), 2);

	// Different core should contribute independently.
	iface_increment_mac_count(iface_id, 1);
	assert_int_equal(iface_get_total_macs(iface_id), 3);

	iface_decrement_mac_count(iface_id, 0);
	assert_int_equal(iface_get_total_macs(iface_id), 2);

	// Decrement below zero should clamp to 0.
	iface_decrement_mac_count(iface_id, 1);
	iface_decrement_mac_count(iface_id, 1);
	assert_int_equal(iface_get_total_macs(iface_id), 1);

	memset(&l2_iface_security[iface_id], 0, sizeof(l2_iface_security[0]));
	memset(l2_iface_mac_counts[iface_id], 0, sizeof(l2_iface_mac_counts[0]));
}

// Test shutdown-on-violation behavior.
static void test_iface_security_shutdown(void **) {
	uint16_t iface_id = 10;

	memset(&l2_iface_security[iface_id], 0, sizeof(l2_iface_security[0]));

	l2_iface_security[iface_id].shutdown_on_violation = true;
	assert_true(iface_get_shutdown_on_violation(iface_id));
	assert_false(iface_is_shutdown(iface_id));

	iface_shutdown_violation(iface_id);
	assert_true(iface_is_shutdown(iface_id));

	memset(&l2_iface_security[iface_id], 0, sizeof(l2_iface_security[0]));
}

// Test FDB stats accessor bounds.
static void test_fdb_stats_bounds(void **) {
	assert_non_null(fdb_get_stats(0, 0));
	assert_non_null(fdb_get_stats(L2_MAX_BRIDGES - 1, 0));
	assert_null(fdb_get_stats(L2_MAX_BRIDGES, 0));
}

// Test FDB stats increment.
static void test_fdb_stats_increment(void **) {
	uint16_t bridge_id = 5;

	memset(l2_fdb_stats[bridge_id], 0, sizeof(l2_fdb_stats[0]));

	struct fdb_stats *st = fdb_get_stats(bridge_id, 0);
	assert_non_null(st);
	assert_int_equal(st->hit, 0);

	st->hit++;
	st->miss += 3;

	assert_int_equal(fdb_get_stats(bridge_id, 0)->hit, 1);
	assert_int_equal(fdb_get_stats(bridge_id, 0)->miss, 3);

	// Different core should have independent stats.
	struct fdb_stats *st2 = fdb_get_stats(bridge_id, 1);
	assert_int_equal(st2->hit, 0);

	memset(l2_fdb_stats[bridge_id], 0, sizeof(l2_fdb_stats[0]));
}

// Test STP helper defaults (no STP configured).
static void test_stp_defaults(void **) {
	assert_true(stp_port_is_forwarding(NULL, 0));
	assert_true(stp_port_is_learning(NULL, 0));
}

// Test feature accessor helpers with NULL bridge.
static void test_feature_accessors_null(void **) {
	assert_null(bridge_get_stp(NULL));
	assert_null(bridge_get_mcast_snooping(NULL));
	// bridge_get_vlan_filtering removed (deferred)
	assert_null(bridge_get_lldp_config(NULL));
}

int main(void) {
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_iface_security_defaults),
		cmocka_unit_test(test_iface_security_bounds),
		cmocka_unit_test(test_iface_security_mac_limits),
		cmocka_unit_test(test_iface_security_shutdown),
		cmocka_unit_test(test_fdb_stats_bounds),
		cmocka_unit_test(test_fdb_stats_increment),
		cmocka_unit_test(test_stp_defaults),
		cmocka_unit_test(test_feature_accessors_null),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
