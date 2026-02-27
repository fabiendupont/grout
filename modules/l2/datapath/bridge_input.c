// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Robin Jarry

#include <gr_eth.h>
#include <gr_iface.h>
#include <gr_l2_control.h>
#include <gr_log.h>
#include <gr_mbuf.h>
#include <gr_rxtx.h>
#include <gr_trace.h>

#include <rte_ether.h>
#include <rte_lcore.h>

enum edges {
	OUTPUT = 0,
	INPUT,
	FLOOD,
	BRIDGE_INVAL,
	HAIRPIN,
	OUT_IFACE_INVAL,
	FLOOD_DISABLED,
	STORM_DROP,
	EDGE_COUNT
};

struct bridge_input_trace {
	uint16_t iface_id;
	uint16_t bridge_id;
};

static uint16_t bridge_input_process(
	struct rte_graph *graph,
	struct rte_node *node,
	void **objs,
	uint16_t nb_objs
) {
	const struct iface *bridge, *iface;
	const struct iface_info_bridge *br;
	const struct gr_fdb_entry *fdb;
	struct iface_mbuf_data *d;
	struct rte_ether_hdr *eth;
	struct fdb_stats *stats;
	struct rte_mbuf *m;
	ip4_addr_t vtep;
	rte_edge_t edge;
	unsigned lcore_id = rte_lcore_id();

	for (uint16_t i = 0; i < nb_objs; i++) {
		m = objs[i];
		d = iface_mbuf_data(m);
		eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
		fdb = NULL;

		if (gr_mbuf_is_traced(m)) {
			struct bridge_input_trace *t = gr_mbuf_trace_add(m, node, sizeof(*t));
			t->iface_id = d->iface->id;
			t->bridge_id = d->iface->domain_id;
		}

		bridge = iface_from_id(d->iface->domain_id);
		if (bridge == NULL || bridge->type != GR_IFACE_TYPE_BRIDGE) {
			edge = BRIDGE_INVAL;
			goto next;
		}
		br = iface_info_bridge(bridge);
		stats = fdb_get_stats(bridge->id, lcore_id);

		// STP: skip learning and forwarding on blocked ports.
		if (br->stp != NULL && !stp_port_is_learning(bridge, d->iface->id)) {
			edge = BRIDGE_INVAL;
			goto next;
		}

		// Port security: check if interface is shutdown due to violation.
		if (iface_is_shutdown(d->iface->id)) {
			edge = BRIDGE_INVAL;
			goto next;
		}

		if (rte_is_unicast_ether_addr(&eth->src_addr)
		    && !(br->flags & GR_BRIDGE_F_NO_LEARN)) {
			// Port security: check MAC limits before learning.
			uint32_t max_macs = iface_get_max_macs(d->iface->id);
			if (max_macs > 0) {
				uint32_t cur = iface_get_total_macs(d->iface->id);
				if (cur >= max_macs) {
					if (iface_get_shutdown_on_violation(d->iface->id))
						iface_shutdown_violation(d->iface->id);
					edge = BRIDGE_INVAL;
					goto next;
				}
			}
			vtep = (d->iface->type == GR_IFACE_TYPE_VXLAN) ? d->vtep : 0;
			fdb_learn(bridge->id, d->iface->id, &eth->src_addr, d->vlan_id, vtep);
		}

		if (rte_is_unicast_ether_addr(&eth->dst_addr)) {
			fdb = fdb_lookup(bridge->id, &eth->dst_addr, d->vlan_id);
			if (fdb == NULL) {
				if (br->flags & GR_BRIDGE_F_NO_UNKNOWN_UNICAST) {
					edge = FLOOD_DISABLED;
					goto next;
				}
				if (stats)
					stats->miss++;
				edge = FLOOD;
				goto next;
			}
			if (fdb->iface_id == d->iface->id) {
				// Don't forward back to source interface
				edge = HAIRPIN;
				goto next;
			}
			iface = iface_from_id(fdb->iface_id);
			if (iface == NULL) {
				edge = OUT_IFACE_INVAL;
				goto next;
			}
			// Direct output to learned interface
			if (stats)
				stats->hit++;
			d->iface = iface;
			d->vtep = fdb->vtep;

			if (iface->type == GR_IFACE_TYPE_BRIDGE) {
				edge = INPUT;
			} else {
				edge = OUTPUT;
			}
		} else {
			// Broadcast or multicast
			if (rte_is_broadcast_ether_addr(&eth->dst_addr)) {
				if (br->flags & GR_BRIDGE_F_NO_BROADCAST) {
					edge = FLOOD_DISABLED;
					goto next;
				}
			} else {
				// Unknown multicast
				if (br->flags & GR_BRIDGE_F_NO_UNKNOWN_MULTICAST) {
					edge = FLOOD_DISABLED;
					goto next;
				}
			}
			if (stats)
				stats->flood++;
			edge = FLOOD;
		}
next:
		if (edge == FLOOD && (br->flags & GR_BRIDGE_F_NO_FLOOD))
			edge = FLOOD_DISABLED;

		// QoS: meter packet against per-queue rate limit
		if (edge == OUTPUT || edge == FLOOD || edge == INPUT) {
			uint8_t prio = 0;
			if (eth->ether_type == RTE_BE16(RTE_ETHER_TYPE_VLAN)) {
				const struct rte_vlan_hdr *vlan = (const struct
								   rte_vlan_hdr *)(eth + 1);
				prio = (rte_be_to_cpu_16(vlan->vlan_tci) >> 13) & 0x7;
			}
			if (!qos_meter_packet(d->iface->id, lcore_id, prio, rte_pktmbuf_pkt_len(m)))
				edge = STORM_DROP; // reuse storm drop for QoS drops
		}

		// Storm control: meter BUM traffic on the ingress port
		if (edge == FLOOD) {
			uint8_t sc_type;
			if (rte_is_broadcast_ether_addr(&eth->dst_addr))
				sc_type = STORM_TRAFFIC_BROADCAST;
			else if (rte_is_multicast_ether_addr(&eth->dst_addr))
				sc_type = STORM_TRAFFIC_MULTICAST;
			else
				sc_type = STORM_TRAFFIC_UNKNOWN_UC;

			if (!storm_control_meter_packet(
				    d->iface->id, lcore_id, sc_type, rte_pktmbuf_pkt_len(m)
			    ))
				edge = STORM_DROP;
		}

		rte_node_enqueue_x1(graph, node, edge, m);

		// Port mirroring: clone to mirror destination if configured
		if (edge == OUTPUT || edge == FLOOD || edge == INPUT) {
			uint16_t src_iface_id = iface_mbuf_data(m)->iface ?
				iface_mbuf_data(m)->iface->id :
				0;
			uint16_t mirror_dest = port_mirror_get_dest(
				bridge->id, src_iface_id, GR_MIRROR_DIR_INGRESS
			);
			if (mirror_dest != GR_IFACE_ID_UNDEF) {
				const struct iface *dest = iface_from_id(mirror_dest);
				if (dest != NULL && (dest->flags & GR_IFACE_F_UP)) {
					struct rte_mbuf *clone = gr_mbuf_copy(
						m, UINT32_MAX, sizeof(struct mbuf_data)
					);
					if (clone != NULL) {
						mbuf_data(clone)->iface = dest;
						rte_node_enqueue_x1(graph, node, OUTPUT, clone);
					}
				}
			}
		}
	}

	return nb_objs;
}

static int bridge_input_trace_format(char *buf, size_t len, const void *data, size_t /*data_len*/) {
	const struct bridge_input_trace *t = data;
	const struct iface *iface = iface_from_id(t->iface_id);
	const struct iface *bridge = iface_from_id(t->bridge_id);
	return snprintf(
		buf,
		len,
		"iface=%s bridge=%s",
		iface ? iface->name : "[deleted]",
		bridge ? bridge->name : "[deleted]"
	);
}

static void bridge_input_register(void) {
	iface_input_mode_register(GR_IFACE_MODE_BRIDGE, "bridge_input");
	iface_output_type_register(GR_IFACE_TYPE_BRIDGE, "bridge_input");
}

static struct rte_node_register node = {
	.name = "bridge_input",
	.process = bridge_input_process,
	.nb_edges = EDGE_COUNT,
	.next_nodes = {
		[OUTPUT] = "iface_output",
		[INPUT] = "iface_input",
		[FLOOD] = "bridge_flood",
		[BRIDGE_INVAL] = "bridge_input_invalid_domain",
		[HAIRPIN] = "bridge_input_hairpin",
		[OUT_IFACE_INVAL] = "bridge_input_invalid_output",
		[FLOOD_DISABLED] = "bridge_input_flood_disabled",
		[STORM_DROP] = "bridge_input_storm_drop",
	},
};

static struct gr_node_info info = {
	.node = &node,
	.type = GR_NODE_T_L2,
	.register_callback = bridge_input_register,
	.trace_format = bridge_input_trace_format,
};

GR_NODE_REGISTER(info);

GR_DROP_REGISTER(bridge_input_invalid_domain);
GR_DROP_REGISTER(bridge_input_hairpin);
GR_DROP_REGISTER(bridge_input_invalid_output);
GR_DROP_REGISTER(bridge_input_flood_disabled);
GR_DROP_REGISTER(bridge_input_storm_drop);
