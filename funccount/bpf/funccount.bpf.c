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
#define PERF_MAX_STACK_DEPTH 127
#endif

struct stacktrace_event {
	u32 pid;
	char comm[TASK_COMM_LEN];
	u32 kstack;
	u32 ustack;
};

struct exectrace_event {
	u32 pid;
	char comm[TASK_COMM_LEN];
	unsigned char ts[8];
	unsigned char frame0[8];
	u32 frame0_type;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 1024);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} exectrace_pb SEC(".maps");

struct stacktrace_event _stacktrace_event = {};
struct exectrace_event _exectrace_event = {};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, struct stacktrace_event);
	__type(value, u64);
} stack_cnt SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__type(key, u32);
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, 1000);
} stack_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10000);
	__type(key, struct exectrace_event);
	__type(value, int);
} exec_time SEC(".maps");

int self_pid = 0;
int target_pid = 0;
/*
 * 0: stack trace
 * 1: exec trace
 */
int trace_type = 0;

static __always_inline int trace_func(void *ctx)
{
	int pid = bpf_get_current_pid_tgid() >> 32;

	if (pid == self_pid || (target_pid >= 0 && pid != target_pid))
		return 0;

	if (trace_type == 0) { /* stack trace */
		struct stacktrace_event key = {};
		u64 *val, one = 1;

		key.pid = pid;
		bpf_get_current_comm(&key.comm, sizeof(key.comm));
		key.kstack = bpf_get_stackid(ctx, &stack_map,
					     0 | BPF_F_FAST_STACK_CMP);
		key.ustack = bpf_get_stackid(ctx, &stack_map,
					     0 | BPF_F_FAST_STACK_CMP |
						     BPF_F_USER_STACK);
		if ((int)key.kstack < 0 && (int)key.ustack < 0)
			return 0;

		val = bpf_map_lookup_elem(&stack_cnt, &key);
		if (val)
			(*val)++;
		else
			bpf_map_update_elem(&stack_cnt, &key, &one,
					    BPF_NOEXIST);
	} else { /* exec trace */
		struct exectrace_event ekey = {};
		int one = 1;
		u64 ts;

		ekey.pid = pid;
		bpf_get_current_comm(&ekey.comm, sizeof(ekey.comm));
		if (bpf_get_stack(ctx, &ekey.frame0, sizeof(ekey.frame0), 0) <=
		    0) {
			if (bpf_get_stack(ctx, &ekey.frame0,
					  sizeof(ekey.frame0),
					  BPF_F_USER_STACK) <= 0)
				return 0;
			ekey.frame0_type = 1;
		} else {
			ekey.frame0_type = 0;
		}
		ts = bpf_ktime_get_ns();

		__builtin_memcpy(&ekey.ts, &ts, sizeof(ts));
		bpf_map_update_elem(&exec_time, &ekey, &one, BPF_NOEXIST);
	}

	bpf_perf_event_output(ctx, &exectrace_pb, BPF_F_CURRENT_CPU, &pid,
			      sizeof(pid));

	return 0;
}

SEC("tp/")
int stacktrace_tp(void *ctx)
{
	return trace_func(ctx);
}

SEC("kprobe/")
int stacktrace_kb(void *ctx)
{
	return trace_func(ctx);
}

SEC("uprobe/")
int stacktrace_ub(void *ctx)
{
	return trace_func(ctx);
}
