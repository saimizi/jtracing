/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __BOOTSTRAP_H
#define __BOOTSTRAP_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

struct event {
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
	char comm[TASK_COMM_LEN];
	char filename[MAX_FILENAME_LEN];
	bool exit_event;
	pid_t last_signal_pid;
	char last_signal_comm[TASK_COMM_LEN];
	int last_sig;
};

struct kill_event {
	pid_t pid; //killer pid
	int comm[TASK_COMM_LEN]; //killer comm
	int sig;
};
#endif /* __BOOTSTRAP_H */
