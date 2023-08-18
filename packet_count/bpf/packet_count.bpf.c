// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct packet_info {
	u64 rx_packets;
	u64 rx_bytes;
};

#define MAX_NETIF_NUM 128

struct packet_info _packet_info = {};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, MAX_NETIF_NUM);
	__type(key, u32);
	__type(value, struct packet_info);
} xdp_stats_map SEC(".maps");

SEC("xdp")
int xdp_stats_func(struct xdp_md *ctx)
{
	struct packet_info *pi;
	u32 key = ctx->ingress_ifindex;

	pi = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (pi) {
		pi->rx_packets += 1;
		pi->rx_bytes += (u64)((unsigned char *)ctx->data_end -
				     (unsigned char *)ctx->data);
	} else {
		struct packet_info _pi;
		pi = &_pi;
		pi->rx_packets = 1;
		pi->rx_bytes = (u64)((unsigned char *)ctx->data_end -
				     (unsigned char *)ctx->data);
		bpf_map_update_elem(&xdp_stats_map, &key, pi, BPF_ANY);
	}

	return XDP_PASS;
}
