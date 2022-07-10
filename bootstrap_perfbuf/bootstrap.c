// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "bootstrap.h"
#include "bootstrap.skel.h"

static struct env {
	bool verbose;
	long min_duration_ms;
} env;

const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"BPF bootstrap demo application.\n"
"\n"
"It traces process start and exits and shows associated \n"
"information (filename, process duration, PID and PPID, etc).\n"
"\n"
"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{ "duration", 'd', "DURATION-MS", 0, "Minimum process duration (ms) to report" },
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key) {
	case 'v':
		env.verbose = true;
		break;
	case 'd':
		errno = 0;
		env.min_duration_ms = strtol(arg, NULL, 10);
		if (errno || env.min_duration_ms <= 0) {
			fprintf(stderr, "Invalid duration: %s\n", arg);
			argp_usage(state);
		}
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	.doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (!env.verbose)
		return 0;

	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;
	char *signals[] = {
		"HUP","INT","QUIT","ILL","TRAP","ABRT","BUS","FPE","KILL","USR1",
		"SEGV","USR2","PIPE","ALRM","TERM","STKFLT","CHLD",
		"CONT","STOP","TSTP","TTIN","TTOU","URG","XCPU","XFSZ",
		"VTALRM","PROF","WINCH","IO","PWR","SYS","RTMIN",
		"RTMIN+1","RTMIN+2","RTMIN+3","RTMIN+4","RTMIN+5",
		"RTMIN+6","RTMIN+7","RTMIN+8","RTMIN+9","RTMIN+10",
		"RTMIN+11","RTMIN+12","RTMIN+13","RTMIN+14","RTMIN+15",
		"RTMAX-14","RTMAX-13","RTMAX-12","RTMAX-11","RTMAX-10",
		"RTMAX-9","RTMAX-8","RTMAX-7","RTMAX-6","RTMAX-5",
		"RTMAX-4","RTMAX-3","RTMAX-2","RTMAX-1","RTMAX",
	};

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	if (e->exit_event) {
		if (e->last_sig > 0) {
			printf("%-8s %-5s %-16s %-7d %-7d [%u] [%s=%d <- %s(%d)]",
			       ts, "EXIT", e->comm, e->pid, e->ppid, e->exit_code,
			       signals[e->last_sig -1], e->last_sig, e->last_signal_comm, e->last_signal_pid);
		} else {
			printf("%-8s %-5s %-16s %-7d %-7d [%u]",
			       ts, "EXIT", e->comm, e->pid, e->ppid, e->exit_code);
		}

		if (e->duration_ns)
			printf(" (%llums)", e->duration_ns / 1000000);
		printf("\n");
	} else {
		printf("%-8s %-5s %-16s %-7d %-7d %s\n",
		       ts, "EXEC", e->comm, e->pid, e->ppid, e->filename);
	}

}

void lost_event(void *ctx, int cpu, __u64 cnt)
{
	printf("lost: cpu: %d cnt: %lld\n", cpu, cnt);
}

int main(int argc, char **argv)
{
	struct perf_buffer *pb = NULL;
	struct bootstrap_bpf *skel;
	int err;

	/* Parse command line arguments */
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = bootstrap_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* Parameterize BPF code with minimum duration parameter */
	skel->rodata->min_duration_ns = env.min_duration_ms * 1000000ULL;

	/* Load & verify BPF programs */
	err = bootstrap_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = bootstrap_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up perf buffer polling */
	pb = perf_buffer__new(bpf_map__fd(skel->maps.pb),
			32,
			handle_event,
			lost_event,
			NULL,
			NULL);
	if (libbpf_get_error(pb)) {
		err = -1;
		fprintf(stderr, "Failed to create perf buffer\n");
		goto cleanup;
	}


	/* Process events */
	printf("%-8s %-5s %-16s %-7s %-7s %s\n",
	       "TIME", "EVENT", "COMM", "PID", "PPID", "FILENAME/EXIT CODE");
	while (!exiting) {
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	perf_buffer__free(pb);
	bootstrap_bpf__destroy(skel);

	return err < 0 ? -err : 0;
}
