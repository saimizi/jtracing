// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// Error code constants (from errno.h)
#define ENOMEM 12 /* Out of memory */
#define EEXIST 17 /* File exists */
#define ENOENT 2 /* No such file or directory */
#define E2BIG 7 /* Argument list too long (used for map full) */

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

#ifndef PERF_MAX_STACK_DEPTH
#define PERF_MAX_STACK_DEPTH 128
#endif

// Age ranges for histogram display (Statistics Mode only)
#define AGE_RANGE_0_1MIN 0     // 0-1 minute
#define AGE_RANGE_1_5MIN 1     // 1-5 minutes  
#define AGE_RANGE_5_30MIN 2    // 5-30 minutes
#define AGE_RANGE_30MIN_PLUS 3 // 30+ minutes

// Age thresholds in nanoseconds for histogram
#define AGE_THRESHOLD_1MIN (60ULL * 1000000000ULL)    // 1 minute
#define AGE_THRESHOLD_5MIN (300ULL * 1000000000ULL)   // 5 minutes
#define AGE_THRESHOLD_30MIN (1800ULL * 1000000000ULL) // 30 minutes

// Structure to store malloc event data
struct malloc_event {
	u32 tid;
	char comm[TASK_COMM_LEN];
	u32 size;
	u32 free_tid;
	char free_comm[TASK_COMM_LEN];
	u64 sequence;
	s32 ustack_sz;
	u64 ustack[PERF_MAX_STACK_DEPTH];
	s32 free_ustack_sz;
	u64 free_ustack[PERF_MAX_STACK_DEPTH];
	// New age tracking fields (Trace Mode)
	u64 alloc_timestamp_ns; // Allocation timestamp in nanoseconds
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
	// New age tracking fields for Statistics Mode
	u64 oldest_alloc_timestamp;  // Timestamp of oldest unfreed allocation
	u32 total_unfreed_count;     // Count of unfreed allocations for average calculation
	u64 total_age_sum_ns;        // Sum of all allocation ages for average calculation
	u32 age_histogram[4];        // Count of allocations in each age range (for --age-histogram)
};

// Compound key for malloc_event_records to ensure uniqueness
struct malloc_event_key {
	void *ptr;
	u64 sequence;
};

// Map to track sequence numbers for each pointer
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, void *);
	__type(value, u64);
} ptr_sequence SEC(".maps");

// Structure to track allocations between uprobe and uretprobe
struct inflight_alloc {
	u32 size;               // Allocation size from malloc parameter
	u64 timestamp_ns;       // Allocation timestamp from bpf_ktime_get_ns()
};

// Map to track in-flight allocations (between uprobe and uretprobe)
// Key: tid - safe because malloc is not reentrant per thread
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);  // tid
	__type(value, struct inflight_alloc);
} inflight_allocs SEC(".maps");

// Global variables for type export to userspace
// These are used by libbpf-cargo to generate Rust type definitions in
// malloc_free_bss_types
// The Rust code references these as malloc_free_bss_types::malloc_record and
// malloc_free_bss_types::malloc_event
struct malloc_record _malloc_record = {};
struct malloc_event _malloc_event = {};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Configuration variables set from userspace
u32 max_stack_depth = PERF_MAX_STACK_DEPTH;

// Hash map to store malloc event records
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384); // Will be configured from userspace
	__type(key, struct malloc_event_key);
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

// Per-CPU array to store inflight_alloc temporarily (ARM64 BPF verifier compatibility)
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct inflight_alloc);
} inflight_temp_heap SEC(".maps");

// Hash map to store malloc records
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2048); // Will be configured from userspace
	__type(key, u32);
	__type(value, struct malloc_record);
} malloc_records SEC(".maps");

// Statistics counters (expanded for age tracking)
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries,
	       24); // Increased from 20 to accommodate age statistics
	__type(key, u32);
	__type(value, u64);
} stats SEC(".maps");

// Statistics indices
#define STAT_MALLOC_CALLS 0
#define STAT_CALLOC_CALLS 1
#define STAT_REALLOC_CALLS 2
#define STAT_ALIGNED_ALLOC_CALLS 3
#define STAT_FREE_CALLS 4
#define STAT_EVENT_DROPS_MAP_FULL 5
#define STAT_EVENT_DROPS_INVALID_KEY 6
#define STAT_EVENT_DROPS_NOMEM 7
#define STAT_EVENT_DROPS_OTHERS 8
#define STAT_RECORD_DROPS_MAP_FULL 9
#define STAT_RECORD_DROPS_INVALID_KEY 10
#define STAT_RECORD_DROPS_NOMEM 11
#define STAT_RECORD_DROPS_OTHERS 12
#define STAT_SYMBOL_FAILURES 13
#define STAT_ACTIVE_EVENTS 14
#define STAT_ACTIVE_RECORDS 15


int target_pid = 0;

/**
 * Mode selector: controls whether to run in Trace Mode or Statistics Mode
 * 
 * This variable is set by userspace based on CLI flags:
 * - Set to true when: -t, -T, or --min-age is used
 * - Set to false (default): Statistics Mode for aggregate analysis
 * 
 * Statistics Mode (trace_mode = false):
 * - Aggregates statistics per-thread in malloc_records map
 * - Tracks age statistics: oldest allocation, average age, histogram
 * - Minimal memory usage, optimal for production monitoring
 * - Events deleted on free to save memory
 * 
 * Trace Mode (trace_mode = true):
 * - Captures detailed per-allocation events in malloc_event_records map
 * - Preserves individual allocation timestamps and stack traces
 * - Higher memory usage but complete allocation tracking
 * - Events preserved after free for detailed analysis
 * - Enables age filtering with --min-age
 */
bool trace_mode = false;

static void increment_stat(u32 stat_key)
{
	u64 *count = bpf_map_lookup_elem(&stats, &stat_key);
	if (count)
		__sync_fetch_and_add(count, 1);
}

static void increment_event_drop_stat(int ret)
{
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

static void increment_record_drop_stat(int ret)
{
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

// Helper function for age histogram categorization (Statistics Mode)
static u32 calculate_age_histogram_range(u64 alloc_timestamp_ns)
{
	u64 current_time = bpf_ktime_get_ns();

	// Handle potential timestamp issues
	if (current_time < alloc_timestamp_ns) {
		// Clock went backwards or invalid timestamp, treat as newest range
		return AGE_RANGE_0_1MIN;
	}

	u64 age_ns = current_time - alloc_timestamp_ns;

	if (age_ns < AGE_THRESHOLD_1MIN) {
		return AGE_RANGE_0_1MIN;
	} else if (age_ns < AGE_THRESHOLD_5MIN) {
		return AGE_RANGE_1_5MIN;
	} else if (age_ns < AGE_THRESHOLD_30MIN) {
		return AGE_RANGE_5_30MIN;
	} else {
		return AGE_RANGE_30MIN_PLUS;
	}
}

// Helper function for updating age statistics on allocation (Statistics Mode)
static void update_age_statistics(struct malloc_record *record, u64 alloc_timestamp_ns)
{
	// Update oldest allocation timestamp
	if (record->oldest_alloc_timestamp == 0 || 
	    alloc_timestamp_ns < record->oldest_alloc_timestamp) {
		record->oldest_alloc_timestamp = alloc_timestamp_ns;
	}
	
	// Update running totals for average age calculation
	record->total_unfreed_count++;
	record->total_age_sum_ns += alloc_timestamp_ns;
	
	// Update age histogram if needed
	u32 age_range = calculate_age_histogram_range(alloc_timestamp_ns);
	record->age_histogram[age_range]++;
}

// Helper function for updating age statistics on free (Statistics Mode)
static void update_age_statistics_on_free(struct malloc_record *record, u64 freed_timestamp_ns)
{
	// Update unfreed count
	if (record->total_unfreed_count > 0) {
		record->total_unfreed_count--;
		
		// Subtract the freed allocation's timestamp from the sum
		// Note: This is an approximation since we don't track individual allocations
		// in Statistics Mode. We'll use the average timestamp as an estimate.
		if (record->total_unfreed_count > 0) {
			// Avoid division by zero and ensure we don't underflow
			u32 divisor = record->total_unfreed_count + 1;
			if (divisor > 0) {
				u64 avg_timestamp = record->total_age_sum_ns / divisor;
				if (record->total_age_sum_ns >= avg_timestamp) {
					record->total_age_sum_ns -= avg_timestamp;
				} else {
					record->total_age_sum_ns = 0;
				}
			}
		} else {
			// Last allocation freed, reset the sum
			record->total_age_sum_ns = 0;
			record->oldest_alloc_timestamp = 0;
		}
	}
}

// Helper function for common allocation logic
static int handle_alloc_entry(void *ctx, u32 size, u32 stat_type)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u32 tid = (u32)id;

	if (target_pid >= 0 && target_pid != pid)
		return 0;

	increment_stat(stat_type);

	// Store allocation info in inflight map
	// Use per-CPU array to avoid ARM64 BPF verifier stack access issues
	u32 zero = 0;
	struct inflight_alloc *info = bpf_map_lookup_elem(&inflight_temp_heap, &zero);
	if (!info)
		return 0;
	
	info->size = size;
	info->timestamp_ns = bpf_ktime_get_ns();

	bpf_map_update_elem(&inflight_allocs, &tid, info, BPF_ANY);

	return 0;
}

// Uprobe to trace malloc calls
SEC("uprobe/")
int BPF_KPROBE(uprobe_malloc, int size)
{
	return handle_alloc_entry(ctx, size, STAT_MALLOC_CALLS);
}

// Uprobe to trace calloc calls
SEC("uprobe/")
int BPF_KPROBE(uprobe_calloc, size_t nmemb, size_t size)
{
	u32 total_size = nmemb * size;
	return handle_alloc_entry(ctx, total_size, STAT_CALLOC_CALLS);
}

// Uprobe to trace realloc calls
SEC("uprobe/")
int BPF_KPROBE(uprobe_realloc, void *ptr, size_t size)
{
	return handle_alloc_entry(ctx, size, STAT_REALLOC_CALLS);
}

// Uprobe to trace aligned_alloc calls
SEC("uprobe/")
int BPF_KPROBE(uprobe_aligned_alloc, size_t alignment, size_t size)
{
	return handle_alloc_entry(ctx, size, STAT_ALIGNED_ALLOC_CALLS);
}

#define REAL_SIZE(entry) (entry->alloc_size - entry->free_size)

// Helper function for common allocation return logic
static int handle_alloc_return(void *ctx, void *ptr)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 pid = id >> 32;
	u32 tid = (u32)id;

	if (target_pid >= 0 && target_pid != pid)
		return 0;

	// Lookup inflight allocation info
	struct inflight_alloc *info = bpf_map_lookup_elem(&inflight_allocs, &tid);
	if (!info)
		return 0;  // No matching inflight allocation

	u32 size = info->size;
	u64 timestamp_ns = info->timestamp_ns;

	// Clean up inflight entry
	bpf_map_delete_elem(&inflight_allocs, &tid);

	if (!ptr)
		return 0;  // Allocation failed, nothing to track

	// Get and increment sequence number for this pointer
	u64 seq = 0;
	u64 *seq_ptr = bpf_map_lookup_elem(&ptr_sequence, &ptr);
	if (seq_ptr) {
		seq = *seq_ptr + 1;
	}
	bpf_map_update_elem(&ptr_sequence, &ptr, &seq, BPF_ANY);

	if (trace_mode) {
		// Trace Mode: Create malloc event record with full details
		// Use per-CPU array to avoid stack overflow
		u32 zero = 0;
		struct malloc_event *event = bpf_map_lookup_elem(&event_alloc_heap, &zero);
		if (!event)
			return 0;

		event->tid = tid;
		event->size = size;
		event->alloc_timestamp_ns = timestamp_ns;
		event->sequence = seq;
		event->free_tid = 0;  // 0 indicates not freed
		bpf_get_current_comm(event->comm, sizeof(event->comm));

		// Collect stack trace for Trace Mode
		u32 max_depth = max_stack_depth;
		if (max_depth > PERF_MAX_STACK_DEPTH)
			max_depth = PERF_MAX_STACK_DEPTH;
		u32 stack_size = max_depth * sizeof(u64);
		event->ustack_sz = bpf_get_stack(ctx, event->ustack, stack_size, BPF_F_USER_STACK);

		// Store in malloc_event_records
		struct malloc_event_key key = { .ptr = ptr, .sequence = seq };
		int ret = bpf_map_update_elem(&malloc_event_records, &key, event, BPF_ANY);
		if (ret != 0) {
			increment_event_drop_stat(ret);
		} else {
			increment_stat(STAT_ACTIVE_EVENTS);
		}
	} else {
		// Statistics Mode: Update aggregate statistics per process AND create event for size tracking

		// Get or create malloc_record for this PID (per-process tracking)
		struct malloc_record *entry = bpf_map_lookup_elem(&malloc_records, &pid);

		if (!entry) {
			// Create new record - use per-CPU array to avoid stack overflow
			u32 zero = 0;
			struct malloc_record *new = bpf_map_lookup_elem(&alloc_heap, &zero);
			if (!new)
				return 0;

			new->pid = pid;
			new->tid = tid;
			new->alloc_size = size;
			new->free_size = 0;
			new->max_size = size;
			new->max_req_size = size;
			bpf_get_current_comm(new->comm, sizeof(new->comm));

			// Collect stack trace for largest allocation
			u32 max_depth = max_stack_depth;
			if (max_depth > PERF_MAX_STACK_DEPTH)
				max_depth = PERF_MAX_STACK_DEPTH;
			u32 stack_size = max_depth * sizeof(u64);
			new->ustack_sz = bpf_get_stack(ctx, new->ustack, stack_size, BPF_F_USER_STACK);

			// Initialize age tracking
			new->oldest_alloc_timestamp = timestamp_ns;
			new->total_unfreed_count = 1;
			new->total_age_sum_ns = timestamp_ns;

			// Initialize histogram
			for (int i = 0; i < 4; i++) {
				new->age_histogram[i] = 0;
			}
			u32 age_range = calculate_age_histogram_range(timestamp_ns);
			new->age_histogram[age_range] = 1;

			int ret = bpf_map_update_elem(&malloc_records, &pid, new, BPF_ANY);
			if (ret != 0) {
				increment_record_drop_stat(ret);
			} else {
				increment_stat(STAT_ACTIVE_RECORDS);
			}
		} else {
			// Update existing record
			entry->alloc_size += size;

			// Update max sizes
			u32 real_size = entry->alloc_size - entry->free_size;
			if (real_size > entry->max_size) {
				entry->max_size = real_size;
			}

			if (size > entry->max_req_size) {
				entry->max_req_size = size;
				// Update stack trace for largest allocation
				u32 max_depth = max_stack_depth;
				if (max_depth > PERF_MAX_STACK_DEPTH)
					max_depth = PERF_MAX_STACK_DEPTH;
				u32 stack_size = max_depth * sizeof(u64);
				entry->ustack_sz = bpf_get_stack(ctx, entry->ustack, stack_size, BPF_F_USER_STACK);
			}

			// Update age statistics
			update_age_statistics(entry, timestamp_ns);

			bpf_map_update_elem(&malloc_records, &pid, entry, BPF_ANY);
		}

		// Also create malloc_event_record for size tracking (no stack trace)
		// This is needed for accurate free_size calculation
		u32 zero = 0;
		struct malloc_event *event = bpf_map_lookup_elem(&event_alloc_heap, &zero);
		if (event) {
			event->tid = tid;
			event->size = size;
			event->alloc_timestamp_ns = timestamp_ns;
			event->sequence = seq;
			event->ustack_sz = -1;  // No stack trace in Statistics Mode
			event->free_tid = 0;  // Not freed yet
			bpf_get_current_comm(event->comm, sizeof(event->comm));

			struct malloc_event_key key = { .ptr = ptr, .sequence = seq };
			bpf_map_update_elem(&malloc_event_records, &key, event, BPF_ANY);
		}
	}

	return 0;
}

// Uretprobe to trace malloc return values
SEC("uprobe/")
int BPF_KRETPROBE(uretprobe_malloc, void *ptr)
{
	return handle_alloc_return(ctx, ptr);
}

// Uretprobe to trace calloc return values
SEC("uprobe/")
int BPF_KRETPROBE(uretprobe_calloc, void *ptr)
{
	return handle_alloc_return(ctx, ptr);
}

// Uretprobe to trace realloc return values
SEC("uprobe/")
int BPF_KRETPROBE(uretprobe_realloc, void *ptr)
{
	return handle_alloc_return(ctx, ptr);
}

// Uretprobe to trace aligned_alloc return values
SEC("uprobe/")
int BPF_KRETPROBE(uretprobe_aligned_alloc, void *ptr)
{
	return handle_alloc_return(ctx, ptr);
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

	// Get the current sequence number for this pointer
	u64 *seq = bpf_map_lookup_elem(&ptr_sequence, &ptr);
	if (!seq)
		return 0; // No malloc record for this pointer

	// Look up the malloc event to get actual allocation size
	struct malloc_event_key key = { .ptr = ptr, .sequence = *seq };
	struct malloc_event *event = bpf_map_lookup_elem(&malloc_event_records, &key);
	if (!event)
		return 0; // No event found for this pointer

	if (trace_mode) {
		// Trace Mode: Update the malloc event record with free information
		// Keep the event for analysis (don't delete)
		event->free_tid = tid;
		u32 max_depth = max_stack_depth;
		if (max_depth > PERF_MAX_STACK_DEPTH)
			max_depth = PERF_MAX_STACK_DEPTH;
		u32 stack_size = max_depth * sizeof(u64);
		event->free_ustack_sz = bpf_get_stack(ctx, event->free_ustack, stack_size,
						      BPF_F_USER_STACK);
		bpf_get_current_comm(event->free_comm, sizeof(event->free_comm));
		bpf_map_update_elem(&malloc_event_records, &key, event, BPF_ANY);
	} else {
		// Statistics Mode: Update malloc record with actual freed size
		// Get the actual allocation size from the event
		u32 actual_size = event->size;

		// Look up malloc_record by PID (per-process tracking)
		struct malloc_record *entry = bpf_map_lookup_elem(&malloc_records, &pid);
		if (entry) {
			// Update free_size with ACTUAL bytes freed (not just a counter)
			entry->free_size += actual_size;

			// Update age statistics when memory is freed
			u64 current_time = bpf_ktime_get_ns();
			update_age_statistics_on_free(entry, current_time);

			bpf_map_update_elem(&malloc_records, &pid, entry, BPF_ANY);
		}

		// Delete the event to save memory (Statistics Mode only needs events temporarily)
		bpf_map_delete_elem(&malloc_event_records, &key);
	}

	return 0;
}
