#ifndef __NETWORKMONITOR_H
#define __NETWORKMONITOR_H

struct socket_event {
	__u64 ts;
	__u32 len;
	__u32 pkt_type; //if_packet.h #24L
	__u32 ifindex;
	__u16 family;
	__u16 protocol; //ipv4 or ipv6
	__u32 ip_proto; //tcp or udp or icmp
	__u32 saddr_v4;
	__u32 daddr_v4;
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	union {
		__be32 ports;
		__be16 port16[2];
	};
};

#endif /* __NETWORKMONITOR_H */
