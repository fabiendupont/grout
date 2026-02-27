// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#pragma once

#include <gr_iface.h>
#include <gr_l2.h>
#include <gr_module.h>
#include <gr_net_types.h>

#include <rte_ip.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_udp.h>
#include <rte_vxlan.h>

#include <stdint.h>

// Per-core FDB forwarding statistics, indexed by [bridge_slot][lcore_id].
// Track forwarding decisions that generic per-interface iface_stats and
// drop node software stats cannot distinguish.
struct fdb_stats {
	uint64_t hit; // unicast forwarded via FDB lookup
	uint64_t miss; // unknown unicast, sent to flood
	uint64_t flood; // broadcast/multicast, sent to flood
} __rte_cache_aligned;

#define L2_MAX_BRIDGES 256
#define L2_MAX_IFACES GR_MAX_IFACES

extern struct fdb_stats l2_fdb_stats[L2_MAX_BRIDGES][RTE_MAX_LCORE];

static inline struct fdb_stats *fdb_get_stats(uint16_t bridge_id, unsigned lcore_id) {
	if (bridge_id >= L2_MAX_BRIDGES)
		return NULL;
	return &l2_fdb_stats[bridge_id][lcore_id];
}

struct mcast_snooping;

// Storm control traffic types.
#define STORM_TRAFFIC_BROADCAST 0
#define STORM_TRAFFIC_MULTICAST 1
#define STORM_TRAFFIC_UNKNOWN_UC 2

// Storm control: check if a BUM packet should be forwarded.
// Returns true if the packet passes the rate meter or if storm
// control is not configured for this interface/traffic type.
bool storm_control_meter_packet(
	uint16_t iface_id,
	uint16_t lcore_id,
	uint8_t traffic_type,
	uint32_t packet_len
);

// QoS: meter a packet against the per-queue rate limit.
// Returns true if the packet should be forwarded. Classifies the
// packet into a priority queue based on 802.1p CoS or DSCP and
// checks the queue's trTCM meter.
bool qos_meter_packet(uint16_t iface_id, uint16_t lcore_id, uint8_t priority, uint32_t packet_len);

// Port mirroring: check if packets on iface_id should be mirrored.
// Returns the destination port ID or GR_IFACE_ID_UNDEF if no mirroring.
uint16_t port_mirror_get_dest(uint16_t bridge_id, uint16_t iface_id, uint8_t direction);

// Internal bridge info structure.
GR_IFACE_INFO(GR_IFACE_TYPE_BRIDGE, iface_info_bridge, {
	BASE(__gr_iface_info_bridge_base);

	struct iface *members[GR_BRIDGE_MAX_MEMBERS];
	struct mcast_snooping *mcast_snoop;
});

struct mcast_snooping *bridge_get_mcast_snooping(const struct iface *bridge);

// Check if a multicast packet to dst_mac should be forwarded to iface_id.
// Returns true if snooping is disabled, MDB has no entry (flood), or
// iface_id is in the MDB entry's port list.
bool mcast_should_forward(
	const struct iface *bridge,
	const struct rte_ether_addr *dst_mac,
	uint16_t iface_id
);

// Lookup a FDB entry from a MAC address and VLAN
const struct gr_fdb_entry *
fdb_lookup(uint16_t bridge_id, const struct rte_ether_addr *, uint16_t vlan_id);

// Learn a new FDB entry or refresh its last_seen timestamp.
void fdb_learn(
	uint16_t bridge_id,
	uint16_t iface_id,
	const struct rte_ether_addr *,
	uint16_t vlan_id,
	ip4_addr_t vtep
);

// Delete all FDB entries referencing the provided interface.
void fdb_purge_iface(uint16_t iface_id);

// Delete all FDB entries referencing the provided bridge.
void fdb_purge_bridge(uint16_t bridge_id);

struct vxlan_template {
	struct rte_ipv4_hdr ip;
	struct rte_udp_hdr udp;
	struct rte_vxlan_hdr vxlan;
};

GR_IFACE_INFO(GR_IFACE_TYPE_VXLAN, iface_info_vxlan, {
	BASE(gr_iface_info_vxlan);

	struct vxlan_template template;

	uint16_t n_flood_vteps;
	ip4_addr_t *flood_vteps;
});

struct iface *vxlan_get_iface(rte_be32_t vni, uint16_t encap_vrf_id);

// Flood list type callbacks, registered per gr_flood_t.
struct flood_type_ops {
	gr_flood_type_t type;
	int (*add)(const struct gr_flood_entry *, bool exist_ok);
	int (*del)(const struct gr_flood_entry *, bool missing_ok);
	int (*list)(uint16_t vrf_id, struct api_ctx *);
};

void flood_type_register(const struct flood_type_ops *);

#define VXLAN_FLAGS_VNI RTE_BE32(GR_BIT32(27))

static inline rte_be32_t vxlan_decode_vni(rte_be32_t vx_vni) {
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	return (rte_be32_t)((uint32_t)vx_vni >> 8);
#else
	return (rte_be32_t)((uint32_t)(vx_vni & RTE_BE32(0xffffff00)) << 8);
#endif
}

static inline rte_be32_t vxlan_encode_vni(uint32_t vni) {
#if RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	return (rte_be32_t)((uint32_t)vni << 8);
#else
	return (rte_be32_t)((uint32_t)rte_cpu_to_be_32(vni) >> 8);
#endif
}
