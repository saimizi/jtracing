// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 128

#define ARGSIZE 128
#define TOTAL_MAX_ARGS 60
#define DEFAULT_MAXARGS 20
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)

const volatile int max_args = DEFAULT_MAXARGS;

struct event {
	int pid;
	int tid;
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

	int args_count;
	unsigned int args_size;
	unsigned char args[FULL_MAX_ARGS_ARR];
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
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024);
} rb SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 3);
	__type(key, int);
	__type(value, struct event);
} exec_heap SEC(".maps");


const volatile unsigned long long min_duration_ns = 0;

struct trace_event_raw_sys_enter_execve{
	struct trace_entry ent;
	int __syscall_nr;
	char *filename;
	char *const *argv;
	char *const *envp;
	char __data[0];
};

SEC("tp/syscalls/sys_enter_execve")
int handle_exec(struct trace_event_raw_sys_enter_execve *ctx)
{
	struct task_struct *task;
	pid_t pid, tid;
	u64 ts;
	u64 id = bpf_get_current_pid_tgid();
	long ret;

	int exec_index = 0;
	struct event *e = bpf_map_lookup_elem(&exec_heap, &exec_index);
	if (!e)
		return 0;

	/* remember time exec() was executed for this PID */
	pid = id >> 32;
	tid = (u32) id;
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);


	/* don't emit exec events when minimum duration is specified */
	if (min_duration_ns)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->event_type = 0;
	e->pid = pid;
	e->tid = tid;
	e->flag = 0;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	char *p;
	ret = bpf_probe_read_user(&p, sizeof(p), &ctx->filename);
	if (ret == 0) {
		bpf_probe_read_user_str(&e->filename, sizeof(e->filename), p);
	} else {
		e->filename[0] = '\0';
	}

	int i;
	e->args_size = 0;
	e->args_count = 0;
	#pragma unroll
	for (i = 0; i < DEFAULT_MAXARGS; i++) {
		ret = bpf_probe_read_user(&p, sizeof(p), &ctx->argv[i]);
		if (ret < 0)
			break;

		if (e->args_size > LAST_ARG)
			break;

		ret = bpf_probe_read_user_str(&e->args[e->args_size], ARGSIZE, p);
		if (ret <= 0) 
			break;

		e->args_count++;
		e->args_size += ret;
	}

	struct fork_event *fe = bpf_map_lookup_elem(&fork_events, &tid);
	if (fe) {
		__builtin_memcpy(&e->comm2, &fe->comm, sizeof(e->comm2));
		e->flag |= 0x1;
	} 


	bpf_ringbuf_output(&rb, e, sizeof(*e), 0);

	return 0;
}

SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
	struct fork_event fork_entry = {};
	struct fork_event *efork = &fork_entry;
	pid_t child_pid; 
	pid_t parent_pid;

	int fork_index = 2;
	struct event *e = bpf_map_lookup_elem(&exec_heap, &fork_index);
	if (!e)
		return 0;

	bpf_probe_read(&child_pid, sizeof(child_pid), &ctx->child_pid);
	bpf_probe_read(&parent_pid, sizeof(parent_pid), &ctx->parent_pid);

	efork->pid = parent_pid;
	bpf_probe_read_str(&efork->comm, sizeof(efork->comm), &ctx->parent_comm);
	bpf_map_update_elem(&fork_events, &child_pid, efork, BPF_ANY);

	e->event_type = 2;
	e->tid = child_pid;
	e->pid = bpf_get_current_pid_tgid() >> 32;
	e->ppid = parent_pid;
	e->flag = 0;
	bpf_probe_read_str(&e->comm, sizeof(e->comm), &ctx->child_comm);
	

	bpf_ringbuf_output(&rb, e, sizeof(*e), 0);
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
	bpf_probe_read(&killed_pid, sizeof(killed_pid), &p->pid);

	bpf_map_update_elem(&kill_events, &killed_pid, &entry, BPF_ANY);

	//bpf_printk("%s kill sig %d  to pid %d\n", entry.comm, entry.sig, killed_pid);
	
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
	struct task_struct *task;
	struct event entry ={};
	
	pid_t pid, tid;
	u64 id, ts, *start_ts, duration_ns = 0;

	int exit_index = 1;
	struct event *e = bpf_map_lookup_elem(&exec_heap, &exit_index);
	if (!e)
		return 0;
	
	/* get PID and TID of exiting thread/process */
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;

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
	e->tid = tid;
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

	struct fork_event *fe = bpf_map_lookup_elem(&fork_events, &tid);
	if (fe) {
		__builtin_memcpy(&e->comm2, &fe->comm, sizeof(e->comm2));
		bpf_map_delete_elem(&fork_events, &pid);
		e->flag |= 0x1;
	} 

	bpf_ringbuf_output(&rb, e, sizeof(*e), 0);

	return 0;
}

