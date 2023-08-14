// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 128
#endif

struct malloc_event{
	u32 pid;
	u32 tid;
	char comm[TASK_COMM_LEN];
	u32 size;
};


struct malloc_event _malloc_event = {};

struct malloc_max {
	u32 max;
	s32 ustack_sz;
	u64 ustack[PERF_MAX_STACK_DEPTH];
};

struct malloc_max _malloc_max = {};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, void *);
	__type(value, struct malloc_event);
} malloc_records SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct malloc_max);
} max_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct malloc_event);
} heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct malloc_max);
} malloc_max_record SEC(".maps");


int target_pid = 0;


SEC("uprobe/")
int BPF_KPROBE(uprobe_malloc, int size)
{
	struct malloc_event event;
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u32 tid = (u32) id;

	if (target_pid >= 0 && target_pid != pid)
		return 0;

	event.pid = pid;
	event.tid = tid;
	bpf_get_current_comm(&event.comm, sizeof(event.comm));
	event.size = size;
	bpf_map_update_elem(&heap, &event.tid, &event, BPF_NOEXIST);
}

SEC("uprobe/")
int BPF_KRETPROBE(uretprobe_malloc, void *ptr)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u32 tid = (u32) id;
	
	if (target_pid >= 0 && target_pid != pid)
		return 0;

	struct malloc_event *entry = bpf_map_lookup_elem(&heap, &tid);
	if (!entry)
		return 0;

	if (ptr) {
		u32 zero = 0;
		struct malloc_max *max_entry = bpf_map_lookup_elem(&malloc_max_record, &pid);
		if (!max_entry || (max_entry && (max_entry->max < entry->size))) {
			struct malloc_max *new = bpf_map_lookup_elem(&max_heap, &zero);
			if (new) {
				new->max = entry->size;
				new->ustack_sz = bpf_get_stack(ctx, new->ustack, sizeof(new->ustack), BPF_F_USER_STACK);
				bpf_map_update_elem(&malloc_max_record, &pid, new, BPF_ANY);
			}
		}

		bpf_map_update_elem(&malloc_records, &ptr, entry, BPF_NOEXIST);
	}

	bpf_map_delete_elem(&heap, &tid);
}

SEC("uprobe/")
int BPF_KPROBE(uprobe_free, void *ptr)
{
	u32 *entry = bpf_map_lookup_elem(&malloc_records, &ptr);
	if (entry) {
		bpf_map_delete_elem(&malloc_records, &ptr);
	}

	return 0;
}
