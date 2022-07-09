// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	int exit_event;
	pid_t last_signal_pid;
	char last_signal_comm[TASK_COMM_LEN];
	int last_sig;
};

struct kill_event {
	pid_t pid; //killer pid
	int comm[TASK_COMM_LEN]; //killer comm
	int sig;
};

struct event _event = {};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, struct kill_event);
} kill_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 4192);
	__type(key, int);
	__type(value, int);
} pb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 2);
	__type(key, int);
	__type(value, struct event);
} exec_heap SEC(".maps");


const volatile unsigned long long min_duration_ns = 0;

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	unsigned fname_off;
	struct event entry ={};
	struct event *e = &entry;
	pid_t pid;
	u64 ts;

	/* remember time exec() was executed for this PID */
	pid = bpf_get_current_pid_tgid() >> 32;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);


	/* don't emit exec events when minimum duration is specified */
	if (min_duration_ns)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = 0;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	int exec_index = 0;
	int err = bpf_map_update_elem(&exec_heap, &exec_index, e, BPF_ANY);
	if (err)
		return 0;

	bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));

	return 0;
}

struct trace_event_raw_sys_enter_kill {
	struct trace_entry ent;
	int __syscall_nr;
	u64 pid;
	u64 sig;
	char __data[0];
};

SEC("tp/syscalls/sys_enter_kill")
int handle_kill(struct trace_event_raw_sys_enter_kill *ctx)
{
	struct kill_event entry = {};
	u32 killed_pid = (u32)ctx->pid;

	entry.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&entry.comm, sizeof(entry.comm));
	entry.sig = (int) ctx->sig;
	bpf_map_update_elem(&kill_events, &killed_pid, &entry, BPF_ANY);

	//bpf_printk("%s kill sig %d  to pid %d\n", entry.comm, entry.sig, killed_pid);

	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
	struct task_struct *task;
	struct event entry ={};
	struct event *e = &entry;
	pid_t pid, tid;
	u64 id, ts, *start_ts, duration_ns = 0;
	
	/* get PID and TID of exiting thread/process */
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;

	/* ignore thread exits */
	if (pid != tid)
		return 0;

	/* if we recorded start of the process, calculate lifetime duration */
	start_ts = bpf_map_lookup_elem(&exec_start, &pid);
	if (start_ts)
		duration_ns = bpf_ktime_get_ns() - *start_ts;
	else if (min_duration_ns)
		return 0;

	bpf_map_delete_elem(&exec_start, &pid);

	/* if process didn't live long enough, return early */
	if (min_duration_ns && duration_ns < min_duration_ns)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->exit_event = 1;
	e->duration_ns = duration_ns;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	struct kill_event *ke = bpf_map_lookup_elem(&kill_events, &pid);
	if (ke) {
		e->last_signal_pid = ke->pid;
		__builtin_memcpy(&e->last_signal_comm, &ke->comm, sizeof(e->last_signal_comm));
		e->last_sig = ke->sig;
		bpf_map_delete_elem(&kill_events, &pid);
	} else {
		e->last_sig = -1; //-1 means no signal.
	}

	int exit_index = 1;
	int err = bpf_map_update_elem(&exec_heap, &exit_index, e, BPF_ANY);
	if (err)
		return 0;

	bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));

	return 0;
}

