#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "tcpconnect.h"

/* Define here, because there are conflicts with include files */
#define AF_INET		2
#define AF_INET6	10

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);
	__type(value, struct sock *);
} sockets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct ipv4_flow_key);
	__type(value, u64);
} ipv4_count SEC(".maps");

static  __always_inline void count_v4(struct sock *sk, __u16 sport, __u16 dport)
{
	struct ipv4_flow_key key = {};
	// static __u64 zero;
	__u64 *val;

	BPF_CORE_READ_INTO(&key.saddr, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&key.daddr, sk, __sk_common.skc_daddr);
	key.sport = bpf_ntohs(sport);
	key.dport = bpf_ntohs(dport);
    // bpf_printk("source port: %d, dest port: %d", bpf_ntohs(sport), bpf_ntohs(dport));
	val = bpf_map_lookup_elem(&ipv4_count, &key);

    __u64 tmp = 1;

	if (val)
		__atomic_add_fetch(val, 1, __ATOMIC_RELAXED);
    else {
        bpf_map_update_elem(&ipv4_count, &key, &tmp, 0);
    }
}

static __always_inline int
enter_tcp_connect(struct pt_regs *ctx, struct sock *sk)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	// __u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid >> 32;
    bpf_printk("%d", tid);

	// __u32 uid;

	// if (filter_pid && pid != filter_pid)
	// 	return 0;

	// uid = bpf_get_current_uid_gid();
	// if (filter_uid != (uid_t) -1 && uid != filter_uid)
	// 	return 0;

	bpf_map_update_elem(&sockets, &tid, &sk, 0);
	return 0;
}

static __always_inline int
exit_tcp_connect(struct pt_regs *ctx, int ret, int ip_ver)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	// __u32 pid = pid_tgid >> 32;
	__u32 tid = pid_tgid;
    // bpf_printk("( tcp connect / exit ) process id: %d", pid);
	struct sock **skpp;
	struct sock *sk;
	__u16 sport = 0;
	__u16 dport;

	skpp = bpf_map_lookup_elem(&sockets, &tid);
	if (!skpp)
		return 0;

	if (ret)
		goto end;

	sk = *skpp;

	BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);

	// if (filter_port(dport))
	// 	goto end;

    if (ip_ver == 4)
        count_v4(sk, sport, dport);
    // else
    //     count_v6(sk, sport, dport);

end:
	bpf_map_delete_elem(&sockets, &tid);
	return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kp_tcp_v4, struct sock *sk)
{
	return enter_tcp_connect(ctx, sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KPROBE(krp_tcp_v4, int ret)
{
	return exit_tcp_connect(ctx, ret, 4);
}
