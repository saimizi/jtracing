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

	/* event_type
	 * 0: exec
	 * 1: exit
	 * 2: fork
	 */
	int event_type;

	pid_t last_signal_pid;
	int last_sig;
	char last_sig_comm[TASK_COMM_LEN];

	/*
	 * exec: save the parent comm
	 * exit: save the parent comm
	 */
	char comm2[TASK_COMM_LEN];

	/*
	 * 0x1: paraent comm saved in comm2;
	 */
	u32 flag;
};

struct kill_event {
	pid_t pid; //killer pid
	int comm[TASK_COMM_LEN]; //killer comm
	int sig;
};

struct fork_event {
	pid_t pid; //parent pid
	int comm[TASK_COMM_LEN]; //parent comm
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
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, struct fork_event);
} fork_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(max_entries, 4192);
	__type(key, int);
	__type(value, int);
} pb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 3);
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

	e->event_type = 0;
	e->pid = pid;
	e->flag = 0;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);


	struct fork_event *fe = bpf_map_lookup_elem(&fork_events, &pid);
	if (fe) {
		__builtin_memcpy(&e->comm2, &fe->comm, sizeof(e->comm2));
		e->flag |= 0x1;
	} 

	int exec_index = 0;
	int err = bpf_map_update_elem(&exec_heap, &exec_index, e, BPF_ANY);
	if (err)
		return 0;

	bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));

	return 0;
}

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	struct event entry ={};
	struct event *e = &entry;
	struct fork_event fork_entry = {};
	struct fork_event *efork = &fork_entry;
	pid_t child_pid; 
	pid_t parent_pid;

	bpf_core_read(&child_pid, sizeof(child_pid), &ctx->child_pid);
	bpf_core_read(&parent_pid, sizeof(parent_pid), &ctx->parent_pid);

	efork->pid = parent_pid;
	bpf_core_read_str(&efork->comm, sizeof(efork->comm), &ctx->parent_comm);
	bpf_map_update_elem(&fork_events, &child_pid, efork, BPF_ANY);

	e->event_type = 2;
	e->pid = child_pid;
	e->ppid = parent_pid;
	e->flag = 0;
	bpf_core_read_str(&e->comm, sizeof(e->comm), &ctx->child_comm);
	
	int exec_index = 2;
	int err = bpf_map_update_elem(&exec_heap, &exec_index, e, BPF_ANY);
	if (err)
		return 0;

	bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));
	return 0;
}

#if 0
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
#endif

SEC("kprobe/do_send_sig_info")
int BPF_KPROBE(do_send_sig_info, int sig, struct kernel_siginfo *info, struct task_struct *p, enum pid_type type)
{
	struct kill_event entry = {};

	entry.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&entry.comm, sizeof(entry.comm));
	entry.sig = sig;

	u32 killed_pid;
	bpf_core_read(&killed_pid, sizeof(killed_pid), &p->pid);

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

	e->event_type = 1;
	e->duration_ns = duration_ns;
	e->pid = pid;
	e->flag = 0;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	struct kill_event *ke = bpf_map_lookup_elem(&kill_events, &pid);
	if (ke) {
		e->last_signal_pid = ke->pid;
		__builtin_memcpy(&e->last_sig_comm, &ke->comm, sizeof(e->last_sig_comm));
		e->last_sig = ke->sig;
		bpf_map_delete_elem(&kill_events, &pid);
	} else {
		e->last_sig = -1; //-1 means no signal.
	}

	struct fork_event *fe = bpf_map_lookup_elem(&fork_events, &pid);
	if (fe) {
		__builtin_memcpy(&e->comm2, &fe->comm, sizeof(e->comm2));
		bpf_map_delete_elem(&fork_events, &pid);
		e->flag |= 0x1;
	} 

	int exit_index = 1;
	int err = bpf_map_update_elem(&exec_heap, &exit_index, e, BPF_ANY);
	if (err)
		return 0;

	bpf_perf_event_output(ctx, &pb, BPF_F_CURRENT_CPU, e, sizeof(*e));

	return 0;
}

