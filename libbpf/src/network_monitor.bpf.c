#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <sys/socket.h>
#include <string.h>
#include <bpf/bpf_endian.h>
#include "network_monitor.h"
#define MAX_ENTRIES 128

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, MAX_ENTRIES);
} ringbuf SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, __u64);
	__type(value, __u64);
} hashmap SEC(".maps");

SEC("socket")
int bpf_prog(struct __sk_buff *skb)
{
	__u64 ts = bpf_ktime_get_ns();
	struct socket_event *d;
	// __u32 pid = bpf_get_current_pid_tgid() >> 32;

	__u16 proto;
	__u32 nhoff = ETH_HLEN; //网络数据包包头：MAC_6+MAC_6+PROTO_2，一共14字节

	bpf_skb_load_bytes(skb, 12, &proto, 2);
	if (proto != __bpf_htons(ETH_P_IP) && proto != __bpf_htons(ETH_P_IPV6)) {
		return 0;
	}

	d = bpf_ringbuf_reserve(&ringbuf, sizeof(*d), 0);
	if (!d) {
		return 0;
	}

	if (proto == __bpf_htons(ETH_P_IP)) { //ipv4
		d->family = AF_INET;
		d->ip_proto = 0;
		bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &d->ip_proto, 1);

		//TODO?? 隧道相关？？
		if (d->ip_proto != IPPROTO_GRE) {
			bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr),
					   &(d->saddr_v4), 4);
			bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr),
					   &(d->daddr_v4), 4);
		}
		//verlen 为ip报文中首部的长度，一般为5（5 x 4B ＝ 20B）
		//https://blog.csdn.net/marywang56/article/details/78051556
		__u8 verlen;
		bpf_skb_load_bytes(skb, nhoff + 0, &verlen, 1);
		//按照ip报文格式，真正的首部长度是第四位，在 *4B 换算成真正的长度（一般为20）。
		//意义为跳过ip报头，获取TCP or UDP 头部4B，即为端口信息
		if (d->ip_proto == IPPROTO_TCP || d->ip_proto == IPPROTO_UDP ||
		    d->ip_proto == IPPROTO_MPTCP) {
			bpf_skb_load_bytes(skb, nhoff + ((verlen & 0xF) << 2), &(d->ports), 4);
		} else {
			d->ports = 0;
		}
	} else { //ipv6
		d->family = AF_INET6;

		__u8 nexthdr;
		bpf_skb_load_bytes(skb, nhoff + offsetof(struct ipv6hdr, nexthdr), &nexthdr, 1);
		d->ip_proto = nexthdr;

		bpf_skb_load_bytes(skb, nhoff + offsetof(struct ipv6hdr, saddr), &(d->saddr_v6),
				   16);
		bpf_skb_load_bytes(skb, nhoff + offsetof(struct ipv6hdr, daddr), &(d->daddr_v6),
				   16);

		__be16 verlen = 40; //报头长度 定长
		if (d->ip_proto == IPPROTO_TCP || d->ip_proto == IPPROTO_UDP ||
		    d->ip_proto == IPPROTO_MPTCP) {
			bpf_skb_load_bytes(skb, nhoff + verlen, &(d->ports), 4);
		} else {
			d->ports = 0;
		}
	}
	//meta info
	d->pkt_type = skb->pkt_type;
	d->ifindex = skb->ifindex;
	d->ts = ts;
	d->len = skb->len;
	d->ifindex = skb->ifindex;
	bpf_ringbuf_submit(d, 0);
	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
