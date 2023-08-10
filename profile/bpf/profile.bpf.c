// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
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

struct event {
	u32 pid;
	u32 tid;
	u32 cpu_id;
	char comm[TASK_COMM_LEN];
	s32 kstack_sz;
	s32 ustack_sz;
	u64 kstack[PERF_MAX_STACK_DEPTH];
	u64 ustack[PERF_MAX_STACK_DEPTH];
};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 8192);
	__type(key, int);
	__type(value, int);
} pb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, int);
	__type(value, struct event);
} heap SEC(".maps");


struct event _event = {};

int trace_idle = 0;
int target_pid = -1;

SEC("perf_event")
int do_perf_event(struct bpf_perf_event_data *ctx)
{
	struct task_struct *task;
	u64 ts;
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	u32 pid = id;
	int cpu_id = bpf_get_smp_processor_id();
	long ret;

	if (!trace_idle && pid == 0)
		return 0;

	if (target_pid >= 0 &&
		target_pid != tgid && target_pid != pid)
		return 0;

	int zero = 0;
	struct event *e = bpf_map_lookup_elem(&heap, &zero);
	if (!e)
		return 0;

	/* remember time exec() was executed for this PID */
	e->pid = tgid;
	e->tid = pid;
	e-> cpu_id = cpu_id;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	e->kstack_sz = bpf_get_stack(ctx, e->kstack, sizeof(e->kstack), 0);
	e->ustack_sz = bpf_get_stack(ctx, e->ustack, sizeof(e->ustack), BPF_F_USER_STACK);

	bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));

	return 0;
}
