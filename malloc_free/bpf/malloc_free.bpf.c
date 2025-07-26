// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Error code constants (from errno.h)
#define ENOMEM 12   /* Out of memory */
#define EEXIST 17   /* File exists */
#define ENOENT 2    /* No such file or directory */
#define E2BIG  7    /* Argument list too long (used for map full) */

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 128
#endif

// Structure to store malloc event data
struct malloc_event {
	u32 tid;
	char comm[TASK_COMM_LEN];
	u32 size;
	u32 free_tid;
	char free_comm[TASK_COMM_LEN];
	s32 ustack_sz;
	u64 ustack[PERF_MAX_STACK_DEPTH];
	s32 free_ustack_sz;
	u64 free_ustack[PERF_MAX_STACK_DEPTH];
};

// Structure to store malloc record data
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
struct malloc_event _malloc_event = {};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Configuration variables set from userspace  
u32 max_stack_depth = PERF_MAX_STACK_DEPTH;

// Hash map to store malloc event records
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384); // Will be configured from userspace
	__type(key, void *);
	__type(value, struct malloc_event);
} malloc_event_records SEC(".maps");

// Per-CPU array to store malloc records
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct malloc_record);
} alloc_heap SEC(".maps");

// Per-CPU array to store malloc events
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct malloc_event);
} event_alloc_heap SEC(".maps");


// Hash map to store malloc records
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048); // Will be configured from userspace
	__type(key, u32);
	__type(value, struct malloc_record);
} malloc_records SEC(".maps");

// Statistics counters
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 16);
	__type(key, u32);
	__type(value, u64);
} stats SEC(".maps");

// Statistics indices
#define STAT_MALLOC_CALLS 0
#define STAT_FREE_CALLS 1
#define STAT_EVENT_DROPS_MAP_FULL 2
#define STAT_EVENT_DROPS_INVALID_KEY 3
#define STAT_EVENT_DROPS_NOMEM 4
#define STAT_EVENT_DROPS_OTHERS 5
#define STAT_RECORD_DROPS_MAP_FULL 6
#define STAT_RECORD_DROPS_INVALID_KEY 7
#define STAT_RECORD_DROPS_NOMEM 8
#define STAT_RECORD_DROPS_OTHERS 9
#define STAT_SYMBOL_FAILURES 10
#define STAT_ACTIVE_EVENTS 11
#define STAT_ACTIVE_RECORDS 12

int target_pid = 0;
bool trace_path = false;

static void increment_stat(u32 stat_key) {
	u64 *count = bpf_map_lookup_elem(&stats, &stat_key);
	if (count)
		__sync_fetch_and_add(count, 1);
}

static void increment_event_drop_stat(int ret) {
	switch (ret) {
	case -E2BIG:
		increment_stat(STAT_EVENT_DROPS_MAP_FULL);
		break;
	case -EEXIST:
	case -ENOENT:
		increment_stat(STAT_EVENT_DROPS_INVALID_KEY);
		break;
	case -ENOMEM:
		increment_stat(STAT_EVENT_DROPS_NOMEM);
		break;
	default:
		increment_stat(STAT_EVENT_DROPS_OTHERS);
		break;
	}
}

static void increment_record_drop_stat(int ret) {
	switch (ret) {
	case -E2BIG:
		increment_stat(STAT_RECORD_DROPS_MAP_FULL);
		break;
	case -EEXIST:
	case -ENOENT:
		increment_stat(STAT_RECORD_DROPS_INVALID_KEY);
		break;
	case -ENOMEM:
		increment_stat(STAT_RECORD_DROPS_NOMEM);
		break;
	default:
		increment_stat(STAT_RECORD_DROPS_OTHERS);
		break;
	}
}

// Uprobe to trace malloc calls
SEC("uprobe/")
int BPF_KPROBE(uprobe_malloc, int size)
{
	u32 zero = 0;
	struct malloc_event *event =
		bpf_map_lookup_elem(&event_alloc_heap, &zero);
	if (!event)
		return 0;

	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u32 tid = (u32)id;

	if (target_pid >= 0 && target_pid != pid)
		return 0;

	increment_stat(STAT_MALLOC_CALLS);

	event->size = size;
	event->tid = tid;
	if (trace_path) {
		u32 max_depth = max_stack_depth;
		if (max_depth > PERF_MAX_STACK_DEPTH)
			max_depth = PERF_MAX_STACK_DEPTH;
		u32 stack_size = max_depth * sizeof(u64);
		event->ustack_sz =
			bpf_get_stack(ctx, event->ustack, stack_size,
				      BPF_F_USER_STACK);
	} else {
		event->ustack_sz = -1;
	}
	
	// Event data is now stored in per-CPU event_alloc_heap, no need to update

	return 0;
}

#define REAL_SIZE(entry) (entry->alloc_size - entry->free_size)

// Uretprobe to trace malloc return values
SEC("uprobe/")
int BPF_KRETPROBE(uretprobe_malloc, void *ptr)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u32 tid = (u32)id;

	if (target_pid >= 0 && target_pid != pid)
		return 0;

	u32 zero = 0;
	struct malloc_event *e = bpf_map_lookup_elem(&event_alloc_heap, &zero);
	if (!e)
		return 0;

	if (ptr) {
		if (trace_path) {
			e->free_tid = -1;
			bpf_get_current_comm(e->comm, sizeof(e->comm));
			bpf_get_current_comm(e->free_comm,
					     sizeof(e->free_comm));
			int ret = bpf_map_update_elem(&malloc_event_records, &ptr, e,
					    BPF_NOEXIST);
			if (ret != 0) {
				increment_event_drop_stat(ret);
			} else {
				increment_stat(STAT_ACTIVE_EVENTS);
			}
		} else {
			// Create a new malloc record if one doesn't exist
			u32 zero = 0;
			struct malloc_record *entry =
				bpf_map_lookup_elem(&malloc_records, &e->tid);
			if (!entry) {
				struct malloc_record *new =
					bpf_map_lookup_elem(&alloc_heap, &zero);
				if (new) {
					new->pid = pid;
					// Note e->tid is same to tid.
					new->tid = e->tid;
					new->alloc_size = e->size;
					new->free_size = 0;
					new->max_size = e->size;
					new->max_req_size = e->size;
					bpf_get_current_comm(new->comm,
							     sizeof(new->comm));
					new->ustack_sz = bpf_get_stack(
						ctx, new->ustack,
						sizeof(new->ustack),
						BPF_F_USER_STACK);

					int ret = bpf_map_update_elem(&malloc_records,
							    &e->tid, new,
							    BPF_ANY);
					if (ret != 0) {
						increment_record_drop_stat(ret);
					} else {
						increment_stat(STAT_ACTIVE_RECORDS);
					}
				}
			} else {
				// Update existing malloc record
				entry->alloc_size += e->size;
				if (REAL_SIZE(entry) > entry->max_size) {
					entry->max_size = REAL_SIZE(entry);
				}

				if (e->size > entry->max_req_size) {
					entry->max_req_size = e->size;
					entry->ustack_sz = bpf_get_stack(
						ctx, entry->ustack,
						sizeof(entry->ustack),
						BPF_F_USER_STACK);
				}

				bpf_map_update_elem(&malloc_records, &e->tid,
						    entry, BPF_ANY);
			}

			// Store the malloc event record
			int ret = bpf_map_update_elem(&malloc_event_records, &ptr, e,
					    BPF_NOEXIST);
			if (ret != 0) {
				increment_event_drop_stat(ret);
			}
		}
	}

	// No cleanup needed for per-CPU event_alloc_heap
}

// Uprobe to trace free calls
SEC("uprobe/")
int BPF_KPROBE(uprobe_free, void *ptr)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u32 tid = (u32)id;

	if (target_pid >= 0 && target_pid != pid)
		return 0;

	increment_stat(STAT_FREE_CALLS);

	// Look up the malloc event record
	struct malloc_event *e =
		bpf_map_lookup_elem(&malloc_event_records, &ptr);
	if (e) {
		if (trace_path) {
			e->free_tid = tid;
			u32 max_depth = max_stack_depth;
			if (max_depth > PERF_MAX_STACK_DEPTH)
				max_depth = PERF_MAX_STACK_DEPTH;
			u32 stack_size = max_depth * sizeof(u64);
			e->free_ustack_sz =
				bpf_get_stack(ctx, e->free_ustack,
					      stack_size,
					      BPF_F_USER_STACK);
			bpf_get_current_comm(e->free_comm,
					     sizeof(e->free_comm));
			bpf_map_update_elem(&malloc_event_records, &ptr, e,
					    BPF_ANY);
		} else {
			/* Update the malloc record
			 * note the record is stored in the key of tid which malloc
			 * happened. it might be different from the current thread.
			 */
			struct malloc_record *entry =
				bpf_map_lookup_elem(&malloc_records, &e->tid);
			if (entry) {
				entry->free_size += e->size;
				bpf_map_update_elem(&malloc_records, &e->tid,
						    entry, BPF_ANY);
			}

			// Delete the malloc event record
			bpf_map_delete_elem(&malloc_event_records, &ptr);
		}
	}

	return 0;
}
