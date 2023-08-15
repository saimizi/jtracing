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
	u32 size;
};

struct malloc_record {
	u32 pid;
	u32 tid;
	char comm[TASK_COMM_LEN];
	u32 max_req_size;
	u32 max_size;
	u32 alloc_size;
	u32 free_size;
	s32 ustack_sz;
	u64 ustack[PERF_MAX_STACK_DEPTH];
};

struct malloc_record _malloc_record = {};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, void *);
	__type(value, struct malloc_event);
} malloc_event_records SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct malloc_record);
} alloc_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct malloc_event);
} event_heap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct malloc_record);
} malloc_records SEC(".maps");


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

	event.size = size;
	bpf_map_update_elem(&event_heap, &tid, &event, BPF_NOEXIST);

	return 0;
}

#define REAL_SIZE(entry) (entry->alloc_size - entry->free_size)

SEC("uprobe/")
int BPF_KRETPROBE(uretprobe_malloc, void *ptr)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u32 tid = (u32) id;
	
	if (target_pid >= 0 && target_pid != pid)
		return 0;

	struct malloc_event *e = bpf_map_lookup_elem(&event_heap, &tid);
	if (!e)
		return 0;

	if (ptr) {
		u32 zero = 0;
		struct malloc_record *entry = bpf_map_lookup_elem(&malloc_records, &pid);
		if (!entry) {
			struct malloc_record *new = bpf_map_lookup_elem(&alloc_heap, &zero);
			if (new) {
				new->pid = pid;
				new->tid = tid;
				new->alloc_size = e->size;
				new->free_size = 0;
				new->max_size = e->size;
				new->max_req_size = e->size;
				bpf_get_current_comm(new->comm, sizeof(new->comm));
				new->ustack_sz = bpf_get_stack(ctx,
					new->ustack,
					sizeof(new->ustack),
					BPF_F_USER_STACK);

				bpf_map_update_elem(&malloc_records, &pid, new, BPF_ANY);
			}
		} else {
			entry->alloc_size += e->size;
			if (REAL_SIZE(entry)> entry->max_size) {
				entry->max_size = REAL_SIZE(entry);
			}

			if (e->size > entry->max_req_size) {
				entry->max_req_size = e->size;
				entry->ustack_sz = bpf_get_stack(ctx, 
					entry->ustack,
					sizeof(entry->ustack),
					BPF_F_USER_STACK);
			}

			bpf_map_update_elem(&malloc_records, &pid, entry, BPF_ANY);
		}

		bpf_map_update_elem(&malloc_event_records, &ptr, e, BPF_NOEXIST);
	}

	bpf_map_delete_elem(&event_heap, &tid);
}

SEC("uprobe/")
int BPF_KPROBE(uprobe_free, void *ptr)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u32 tid = (u32) id;

	if (target_pid >= 0 && target_pid != pid)
		return 0;

	struct malloc_event *e= bpf_map_lookup_elem(&malloc_event_records, &ptr);
	if (e) {
		struct malloc_record *entry = bpf_map_lookup_elem(&malloc_records, &pid);
		if (entry) {
			entry->free_size  += e->size;
			bpf_map_update_elem(&malloc_records, &pid, entry, BPF_ANY);
		}

		bpf_map_delete_elem(&malloc_event_records, &ptr);
	}


	return 0;
}
