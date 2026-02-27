// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#pragma once

#include <gr_api.h>
#include <gr_bitops.h>
#include <gr_macro.h>
#include <gr_net_types.h>

#include <stdint.h>

#define GR_L2_MODULE 0xbabe

// Bridge configuration flags.
typedef enum : uint16_t {
	GR_BRIDGE_F_NO_FLOOD = GR_BIT16(0),
	GR_BRIDGE_F_NO_LEARN = GR_BIT16(1),
} gr_bridge_flags_t;

#define GR_BRIDGE_MAX_MEMBERS 64
#define GR_BRIDGE_DEFAULT_AGEING 300

// Bridge reconfiguration attribute flags.
#define GR_BRIDGE_SET_AGEING_TIME GR_BIT64(32)
#define GR_BRIDGE_SET_FLAGS GR_BIT64(33)
#define GR_BRIDGE_SET_MAC GR_BIT64(34)

struct __gr_iface_info_bridge_base {
	uint16_t ageing_time; // Learned MAC ageing time in seconds (0 = default)
	gr_bridge_flags_t flags;
	struct rte_ether_addr mac; // Randomly generated if not set explicitly.
	uint16_t n_members;
};

// Info structure for GR_IFACE_TYPE_BRIDGE interfaces.
// Only port, VLAN and bond interfaces can be members.
// Members are reassigned to the default VRF when the bridge is destroyed.
struct gr_iface_info_bridge {
	BASE(__gr_iface_info_bridge_base);
	uint16_t members[GR_BRIDGE_MAX_MEMBERS]; // Interface IDs of bridge members.
};

// VXLAN reconfiguration attribute flags.
#define GR_VXLAN_SET_VNI GR_BIT64(32)
#define GR_VXLAN_SET_ENCAP_VRF GR_BIT64(33)
#define GR_VXLAN_SET_DST_PORT GR_BIT64(34)
#define GR_VXLAN_SET_LOCAL GR_BIT64(35)
#define GR_VXLAN_SET_MAC GR_BIT64(37)

// Info structure for GR_IFACE_TYPE_VXLAN interfaces.
struct gr_iface_info_vxlan {
	uint32_t vni; // VXLAN Network Identifier (24-bit).
	uint16_t encap_vrf_id; // L3 domain for underlay routing.
	uint16_t dst_port; // UDP destination port (default 4789).
	ip4_addr_t local; // Local VTEP IP address (must be a configured address in encap_vrf_id).
	struct rte_ether_addr mac; // Default to random address.
};

// FDB (L2 Forwarding Database) management /////////////////////////////////////

// FDB entry flags.
typedef enum : uint8_t {
	GR_FDB_F_STATIC = GR_BIT8(0), // User-configured, never aged out.
	GR_FDB_F_LEARN = GR_BIT8(1), // Learned via local bridge.
	GR_FDB_F_EXTERN = GR_BIT8(2), // Programmed by external control plane.
} gr_fdb_flags_t;

// Forwarding database entry associating a MAC+VLAN to a bridge member interface.
struct gr_fdb_entry {
	uint16_t bridge_id;
	struct rte_ether_addr mac;
	uint16_t vlan_id;
	uint16_t iface_id; // Updated automatically when a MAC moves between members.
	ip4_addr_t vtep; // Remote VTEP for VXLAN-learned entries, 0 for local.
	gr_fdb_flags_t flags;
	clock_t last_seen; // Refreshed on each datapath hit for learned entries.
};

enum {
	GR_EVENT_FDB_ADD = EVENT_TYPE(GR_L2_MODULE, 0x0001),
	GR_EVENT_FDB_DEL = EVENT_TYPE(GR_L2_MODULE, 0x0002),
	GR_EVENT_FDB_UPDATE = EVENT_TYPE(GR_L2_MODULE, 0x0003),
};

// Add an FDB entry. The bridge_id is resolved from the member interface's domain.
// Entries without GR_FDB_F_STATIC are subject to ageing like learned entries.
#define GR_FDB_ADD REQUEST_TYPE(GR_L2_MODULE, 0x0001)

struct gr_fdb_add_req {
	struct gr_fdb_entry fdb;
	bool exist_ok; // If true, update existing entry instead of returning EEXIST.
};

// struct gr_fdb_add_resp { };

// Delete an FDB entry by key.
#define GR_FDB_DEL REQUEST_TYPE(GR_L2_MODULE, 0x0002)

struct gr_fdb_del_req {
	uint16_t bridge_id;
	struct rte_ether_addr mac;
	uint16_t vlan_id;
	bool missing_ok; // If true, ignore ENOENT.
};

// Flush FDB entries. All non-zero fields are ANDed as filters.
#define GR_FDB_FLUSH REQUEST_TYPE(GR_L2_MODULE, 0x0003)

struct gr_fdb_flush_req {
	uint16_t bridge_id; // GR_IFACE_ID_UNDEF to match all bridges.
	struct rte_ether_addr mac; // Zero address to match all MACs.
	uint16_t iface_id; // GR_IFACE_ID_UNDEF to match all interfaces.
	gr_fdb_flags_t flags; // GR_FDB_F_STATIC: flush all. Otherwise, only dynamic entries.
};

// struct gr_fdb_flush_resp { };

// List FDB entries with optional filtering.
#define GR_FDB_LIST REQUEST_TYPE(GR_L2_MODULE, 0x0004)

struct gr_fdb_list_req {
	uint16_t bridge_id; // GR_IFACE_ID_UNDEF to list all bridges.
	uint16_t iface_id; // GR_IFACE_ID_UNDEF to match all interfaces.
	gr_fdb_flags_t flags; // GR_FDB_F_STATIC: only static. Otherwise, list all entries.
};

STREAM_RESP(struct gr_fdb_entry);

// Get FDB subsystem configuration and usage.
#define GR_FDB_CONFIG_GET REQUEST_TYPE(GR_L2_MODULE, 0x0005)

// struct gr_fdb_config_get_req { };

struct gr_fdb_config_get_resp {
	uint32_t max_entries;
	uint32_t used_entries;
};

// Set FDB subsystem configuration.
// Changing max_entries requires the FDB to be empty (returns EBUSY otherwise).
#define GR_FDB_CONFIG_SET REQUEST_TYPE(GR_L2_MODULE, 0x0006)

struct gr_fdb_config_set_req {
	uint32_t max_entries;
};

// struct gr_fdb_config_set_resp { };

// Flood list management for BUM (Broadcast, Unknown unicast, Multicast) //////

typedef enum : uint8_t {
	GR_FLOOD_T_VTEP = 1, // VXLAN remote VTEP
} gr_flood_type_t;

static inline const char *gr_flood_type_name(gr_flood_type_t type) {
	switch (type) {
	case GR_FLOOD_T_VTEP:
		return "vtep";
	}
	return "?";
}

struct gr_flood_vtep {
	uint32_t vni;
	ip4_addr_t addr;
};

struct gr_flood_entry {
	gr_flood_type_t type;
	uint16_t vrf_id;
	union {
		struct gr_flood_vtep vtep;
	};
};

enum {
	GR_EVENT_FLOOD_ADD = EVENT_TYPE(GR_L2_MODULE, 0x0011),
	GR_EVENT_FLOOD_DEL = EVENT_TYPE(GR_L2_MODULE, 0x0012),
};

#define GR_FLOOD_ADD REQUEST_TYPE(GR_L2_MODULE, 0x0011)

struct gr_flood_add_req {
	struct gr_flood_entry entry;
	bool exist_ok;
};

// struct gr_flood_add_resp { };

#define GR_FLOOD_DEL REQUEST_TYPE(GR_L2_MODULE, 0x0012)

struct gr_flood_del_req {
	struct gr_flood_entry entry;
	bool missing_ok;
};

// struct gr_flood_del_resp { };

#define GR_FLOOD_LIST REQUEST_TYPE(GR_L2_MODULE, 0x0013)

struct gr_flood_list_req {
	gr_flood_type_t type; // 0 for all types
	uint16_t vrf_id; // GR_VRF_ID_UNDEF for all
};

STREAM_RESP(struct gr_flood_entry);

// FDB statistics ///////////////////////////////////////////////////////////////

#define GR_L2_FDB_STATS_GET REQUEST_TYPE(GR_L2_MODULE, 0x0020)

struct gr_l2_fdb_stats_get_req {
	uint16_t bridge_id;
};

struct gr_l2_fdb_stats {
	uint16_t bridge_id;
	uint64_t hit; // unicast forwarded via FDB lookup
	uint64_t miss; // unknown unicast, sent to flood
	uint64_t flood; // broadcast/multicast, sent to flood
};

#define GR_L2_FDB_STATS_RESET REQUEST_TYPE(GR_L2_MODULE, 0x0021)

struct gr_l2_fdb_stats_reset_req {
	uint16_t bridge_id;
};

// Multicast snooping (IGMP/MLD) //////////////////////////////////////////////

#define GR_L2_MCAST_SNOOPING_SET REQUEST_TYPE(GR_L2_MODULE, 0x0050)

struct gr_l2_mcast_snooping_req {
	uint16_t bridge_id;
	uint8_t igmp_enabled;
	uint8_t mld_enabled;
	uint16_t query_interval;
	uint16_t max_response_time;
	uint8_t querier_enabled;
	uint32_t aging_time;
};

#define GR_L2_MCAST_SNOOPING_GET REQUEST_TYPE(GR_L2_MODULE, 0x0051)

struct gr_l2_mcast_snooping_status {
	uint16_t bridge_id;
	uint8_t igmp_enabled;
	uint8_t mld_enabled;
	uint16_t query_interval;
	uint16_t max_response_time;
	uint8_t querier_enabled;
	uint32_t aging_time;
	uint32_t mdb_entries;
};

#define GR_L2_MDB_LIST REQUEST_TYPE(GR_L2_MODULE, 0x0052)

struct gr_l2_mdb_entry {
	uint16_t bridge_id;
	struct rte_ether_addr group_mac;
	union {
		ip4_addr_t ip4;
		struct rte_ipv6_addr ip6;
	} group_ip;
	uint8_t ip_version;
	uint16_t n_ports;
	uint16_t ports[32];
	uint8_t is_static;
	uint32_t age;
};

struct gr_l2_mdb_list_req {
	uint16_t bridge_id;
};

#define GR_L2_MDB_ADD REQUEST_TYPE(GR_L2_MODULE, 0x0053)

struct gr_l2_mdb_add_req {
	uint16_t bridge_id;
	struct rte_ether_addr group_mac;
	union {
		ip4_addr_t ip4;
		struct rte_ipv6_addr ip6;
	} group_ip;
	uint8_t ip_version;
	uint16_t iface_id;
};

#define GR_L2_MDB_DEL REQUEST_TYPE(GR_L2_MODULE, 0x0054)

struct gr_l2_mdb_del_req {
	uint16_t bridge_id;
	struct rte_ether_addr group_mac;
	uint16_t iface_id;
};

// Storm control //////////////////////////////////////////////////////////////

#define GR_L2_STORM_CONTROL_SET REQUEST_TYPE(GR_L2_MODULE, 0x0070)

struct gr_l2_storm_control_req {
	uint16_t iface_id;
	uint8_t enabled;
	uint64_t bcast_rate_kbps;
	uint64_t mcast_rate_kbps;
	uint64_t unknown_uc_rate_kbps;
	uint8_t use_pps;
	uint8_t shutdown_on_violation;
	uint8_t violation_threshold;
};

#define GR_L2_STORM_CONTROL_GET REQUEST_TYPE(GR_L2_MODULE, 0x0071)

struct gr_l2_storm_control_get_req {
	uint16_t iface_id;
};

struct gr_l2_storm_control_status {
	uint16_t iface_id;
	uint8_t enabled;
	uint64_t bcast_rate_kbps;
	uint64_t mcast_rate_kbps;
	uint64_t unknown_uc_rate_kbps;
	uint8_t use_pps;
	uint8_t shutdown_on_violation;
	uint8_t violation_threshold;
	uint8_t is_shutdown;
};

#define GR_L2_STORM_CONTROL_REENABLE REQUEST_TYPE(GR_L2_MODULE, 0x0072)

struct gr_l2_storm_control_reenable_req {
	uint16_t iface_id;
};

#define GR_L2_STORM_CONTROL_STATS_GET REQUEST_TYPE(GR_L2_MODULE, 0x0073)

struct gr_l2_storm_control_stats {
	uint16_t iface_id;
	uint64_t bcast_passed;
	uint64_t bcast_dropped;
	uint64_t mcast_passed;
	uint64_t mcast_dropped;
	uint64_t unknown_uc_passed;
	uint64_t unknown_uc_dropped;
	uint64_t shutdown_events;
};

// Port mirroring /////////////////////////////////////////////////////////////

enum gr_mirror_direction {
	GR_MIRROR_DIR_INGRESS = (1 << 0),
	GR_MIRROR_DIR_EGRESS = (1 << 1),
	GR_MIRROR_DIR_BOTH = (GR_MIRROR_DIR_INGRESS | GR_MIRROR_DIR_EGRESS),
};

#define GR_L2_MIRROR_SESSION_SET REQUEST_TYPE(GR_L2_MODULE, 0x0080)

struct gr_l2_mirror_session_req {
	uint16_t bridge_id;
	uint16_t session_id;
	uint8_t enabled;
	uint16_t num_sources;
	uint16_t source_ports[16];
	uint16_t dest_port;
	uint8_t direction;
	uint8_t is_rspan;
	uint16_t rspan_vlan;
};

#define GR_L2_MIRROR_SESSION_GET REQUEST_TYPE(GR_L2_MODULE, 0x0081)

struct gr_l2_mirror_session_get_req {
	uint16_t bridge_id;
	uint16_t session_id;
};

struct gr_l2_mirror_session_status {
	uint16_t bridge_id;
	uint16_t session_id;
	uint8_t enabled;
	uint16_t num_sources;
	uint16_t source_ports[16];
	uint16_t dest_port;
	uint8_t direction;
	uint8_t is_rspan;
	uint16_t rspan_vlan;
	uint64_t packets_mirrored;
};

#define GR_L2_MIRROR_SESSION_DEL REQUEST_TYPE(GR_L2_MODULE, 0x0082)

struct gr_l2_mirror_session_del_req {
	uint16_t bridge_id;
	uint16_t session_id;
};

struct gr_l2_mirror_filter_req {
	uint16_t bridge_id;
	uint16_t session_id;
	uint8_t enabled;
	uint16_t num_vlans;
	uint16_t vlans[64];
	uint16_t ether_type;
	struct rte_ether_addr src_mac;
	struct rte_ether_addr dst_mac;
	uint8_t src_mac_set;
	uint8_t dst_mac_set;
};

#define GR_L2_MIRROR_FILTER_SET REQUEST_TYPE(GR_L2_MODULE, 0x0083)

#define GR_L2_MIRROR_STATS_GET REQUEST_TYPE(GR_L2_MODULE, 0x0084)

struct gr_l2_mirror_stats {
	uint16_t bridge_id;
	uint64_t packets_mirrored;
	uint64_t packets_dropped;
	uint64_t filter_matched;
	uint64_t filter_rejected;
	uint64_t clone_failed;
};
