//go:build ignore
// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Jacky Yin */
#include "vmlinux.h"
#include "sockfilter.h"
// #include "tcpconnect.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
// #include <bpf/bpf_core_read.h>
// #include <bpf/bpf_tracing.h>
// #include <linux/bpf.h>
// #include <linux/if_ether.h>
// #include <linux/in.h>
// #include <linux/ip.h>
// #include <stddef.h>

/* Define here, because there are conflicts with include files */
#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define ETH_HLEN  14
#define ETH_P_IP  0x0800

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff) {
	__u16 frag_off;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	return frag_off & (IP_MF | IP_OFFSET);
}

	// __u64 pid_tgid = bpf_get_current_pid_tgid();
	// __u32 pid = pid_tgid >> 32;
	// __u32 tid = pid_tgid;
	// __u32 uid;

SEC("socket")
int socket_handler(struct __sk_buff *skb) {
    if ( skb->pkt_type != 0 )
        return 0;
    __u16 proto;
    __u32 nhoff = ETH_HLEN;

	bpf_skb_load_bytes(skb, 12, &proto, 2);
	proto = __bpf_ntohs(proto);
	if (proto != ETH_P_IP)
		return 0;

	if (ip_is_fragment(skb, nhoff)) {
		// bpf_printk("%d\n", skb->protocol);
		return 0;
	}

	/* reserve sample from BPF ringbuf */
	// e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	// if (!e)
	// 	return 0;

    __u16 proto2 = 0;
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &proto2, 1);

	if (proto2 != IPPROTO_UDP) {
		// bpf_ringbuf_discard(e, 0);
		return 0;
	}

	// if (e->ip_proto != IPPROTO_GRE) {
	// 	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &(e->src_addr), 4);
	// 	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &(e->dst_addr), 4);
	// }

	// bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);
	// bpf_skb_load_bytes(skb, nhoff + ((verlen & 0xF) << 2), &(e->ports), 4);
	// e->pkt_type = skb->pkt_type;
	// e->ifindex  = skb->ifindex;
	// bpf_ringbuf_discard(e, 0);

	return skb->len;
}
