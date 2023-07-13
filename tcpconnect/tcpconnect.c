// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2020 Anton Protopopov
//
// Based on tcpconnect(8) from BCC by Brendan Gregg
#include <bpf/bpf.h>
// #include <bpf/bpf_helpers.h>
#include "tcpconnect.h"
#include "tcpconnect.skel.h"
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
// #include <bpf/libbpf.h>

// #define SIGINT 2
// #define SIGTERM 16

#define warn(...) fprintf(stderr, __VA_ARGS__)

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;
static void sig_handler(int sig)
{
	exiting = true;
}

// static void print_count_ipv4(int map_fd) {}

void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

int main(int argc, char **argv)
{
	// LIBBPF_OPTS(bpf_object_open_opts, open_opts);

	libbpf_set_print(libbpf_print_fn);
    bump_memlock_rlimit();

    	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

    struct tcpconnect_bpf *skel;
    skel = tcpconnect_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

    // bpf_program__set_type(skel->progs.kp_v4_connect, BPF_PROG_TYPE_KPROBE);
    // bpf_program__set_type(skel->progs.krp_v4_connect, BPF_PROG_TYPE_KPROBE);

    int err;
    err = tcpconnect_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    bpf_map__pin(skel->maps.sockets, "/sys/fs/bpf/sockets");
    bpf_map__pin(skel->maps.ipv4_count, "/sys/fs/bpf/ipv4_count");

    err = tcpconnect_bpf__attach(skel);
	if (err) {
		warn("failed to attach BPF programs: %s\n", strerror(-err));
		goto cleanup;
	}

    while (!exiting) {
        // goto cleanup;
        // print_count_ipv4(bpf_map__fd(skel->maps.ipv4_count));
        sleep(5);
    }

cleanup:
    bpf_map__unpin(skel->maps.sockets, "/sys/fs/bpf/sockets");
    bpf_map__unpin(skel->maps.ipv4_count, "/sys/fs/bpf/ipv4_count");
	tcpconnect_bpf__destroy(skel);
	return -err;
}
