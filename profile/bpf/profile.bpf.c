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
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 8192);
} rb SEC(".maps");

struct event _event = {};

int skip_idle = -1;
int skip_self = -1;

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

	if (skip_idle == pid)
		return 0;

	if (skip_self == pid || skip_self == tgid)
		return 0;


	struct event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* remember time exec() was executed for this PID */
	e->pid = tgid;
	e->tid = pid;
	e-> cpu_id = cpu_id;
	bpf_get_current_comm(e->comm, sizeof(e->comm));
	e->kstack_sz = bpf_get_stack(ctx, e->kstack, sizeof(e->kstack), 0);
	e->ustack_sz = bpf_get_stack(ctx, e->ustack, sizeof(e->ustack), BPF_F_USER_STACK);

	bpf_ringbuf_submit(e, 0);

	return 0;
}
