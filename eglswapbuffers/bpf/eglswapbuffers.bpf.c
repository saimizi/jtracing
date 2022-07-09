// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

struct swap_event{
	u32 pid;  /* Thread ID */
	u32 tgid; 
	char comm[TASK_COMM_LEN];
	u32 duration_ms;
};


struct swap_event _swap_event = {};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, struct swap_event);
	__type(value, u32);
} swap_records SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, u64);
} prev_ts SEC(".maps");

int target_pid = 0;


SEC("uprobe/")
int swap_trace(void *ctx)
{
	struct swap_event event;
	u64 ts = bpf_ktime_get_ns();
	u64 pid_tgid = bpf_get_current_pid_tgid();
	int one = 1;
	u32 pid = pid_tgid >> 32;

	if (target_pid >= 0 && target_pid != pid)
		return 0;

	event.pid = pid;
	event.tgid = (u32)pid_tgid;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	event.duration_ms = 0;

	u64 *pts = bpf_map_lookup_elem(&prev_ts, &event.pid);
	bpf_map_update_elem(&prev_ts, &event.pid, &ts, BPF_ANY);

	if (pts) 
		event.duration_ms = (u32)((ts - *pts) / 1000000);
	else 
		return 0;


	u32 *count = bpf_map_lookup_elem(&swap_records, &event);
	if (count) {
		*count += 1;
	} else {
		bpf_map_update_elem(&swap_records,
				&event, &one, BPF_NOEXIST);
	}

}
