// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Meta Platforms, Inc. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef PARA_LEN
#define PARA_LEN 80
#endif

struct read_line{
	char para[PARA_LEN];
	int len;
	u32 pid;
};


struct read_line _read_line = {};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, sizeof(struct read_line) * 1024);
} rb SEC(".maps");

SEC("uretprobe/")
int BPF_KRETPROBE(uretprobe_readline, char *para)
{

	u64 pid_tgid = bpf_get_current_pid_tgid();
	u32 pid = pid_tgid >> 32;
	u32 tid = pid_tgid;


	struct read_line *entry = bpf_ringbuf_reserve(&rb, sizeof(*entry), 0);
	if (!entry) {
		return 0;
	}

	entry->pid = pid;
	if (para) {
		entry->len = bpf_probe_read_str(entry->para, sizeof(entry->para), para);
		if (entry->len > 0) {
#if 0
			bpf_printk("pid: %d command: %s", pid, entry->para);
#endif
			bpf_ringbuf_submit(entry, 0);
			return 0;
		}
	}

#if 0
	bpf_printk("pid: %d command: null", pid);
#endif

	bpf_ringbuf_discard(entry,0);
	return 0;
}
