// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

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

void update_map(u32 key, u64 bytes)
{
	struct packet_info *pi;

	pi = bpf_map_lookup_elem(&xdp_stats_map, &key);
	if (pi) {
		pi->rx_packets += 1;
		pi->rx_bytes += bytes;
	} else {
		struct packet_info _pi;
		pi = &_pi;
		pi->rx_packets = 1;
		pi->rx_bytes = bytes;
		bpf_map_update_elem(&xdp_stats_map, &key, pi, BPF_ANY);
	}
}

SEC("xdp")
int xdp_stats_func1(struct xdp_md *ctx)
{
	struct packet_info *pi;
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;

	struct ethhdr *eth = data;

	if (eth + 1 > data_end) {
		return XDP_PASS;
	}

	if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
		return XDP_PASS;
	}

	struct iphdr *iph =
		(struct iphdr *)((unsigned char *)data + sizeof(struct ethhdr));
	if (iph + 1 > data_end) {
		return XDP_PASS;
	}

	u32 ip_src = iph->saddr;
	u32 key = ip_src;
	u64 bytes = (u64)(data_end - data);
	update_map(key, bytes);

	return XDP_PASS;
}

SEC("xdp")
int xdp_stats_func2(struct xdp_md *ctx)
{
	struct packet_info *pi;
	u32 key = ctx->ingress_ifindex;

	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	u64 bytes = (u64)(data_end - data);

	update_map(key, bytes);

	return XDP_PASS;
}
