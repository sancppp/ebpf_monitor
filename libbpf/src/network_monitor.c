#include <cjson/cJSON.h>
#include <argp.h>
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/libbpf.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>
#include "network_monitor.h"
#include "network_monitor.skel.h"
#include <librdkafka/rdkafka.h>

static struct env {
	const char *interface;
} env;
bool __debug = 0;

#define MAX_ENTRIES 1024
static const char *ipproto_mapping[IPPROTO_MAX] = {
	[IPPROTO_IP] = "IP",	       [IPPROTO_ICMP] = "ICMP",
	[IPPROTO_IGMP] = "IGMP",       [IPPROTO_IPIP] = "IPIP",
	[IPPROTO_TCP] = "TCP",	       [IPPROTO_EGP] = "EGP",
	[IPPROTO_PUP] = "PUP",	       [IPPROTO_UDP] = "UDP",
	[IPPROTO_IDP] = "IDP",	       [IPPROTO_TP] = "TP",
	[IPPROTO_DCCP] = "DCCP",       [IPPROTO_IPV6] = "IPV6",
	[IPPROTO_RSVP] = "RSVP",       [IPPROTO_GRE] = "GRE",
	[IPPROTO_ESP] = "ESP",	       [IPPROTO_AH] = "AH",
	[IPPROTO_MTP] = "MTP",	       [IPPROTO_BEETPH] = "BEETPH",
	[IPPROTO_ENCAP] = "ENCAP",     [IPPROTO_PIM] = "PIM",
	[IPPROTO_COMP] = "COMP",       [IPPROTO_SCTP] = "SCTP",
	[IPPROTO_UDPLITE] = "UDPLITE", [IPPROTO_MPLS] = "MPLS",
	[IPPROTO_RAW] = "RAW",	       [IPPROTO_MPTCP] = "IPPROTO_MPTCP"
};

//for kafka
rd_kafka_t *producer;
const char *topic = "test"; /* topic to produce to */

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;
static void sig_handler(int sig)
{
	exiting = true;
}

static char *struct2json(void *data)
{
	const struct socket_event *d = data;
	char saddr[INET6_ADDRSTRLEN] = {}, daddr[INET6_ADDRSTRLEN] = {};
	char ifname[IF_NAMESIZE];
	if (!if_indextoname(d->ifindex, ifname))
		return NULL;
	cJSON *root = cJSON_CreateObject();
	if (d->family == AF_INET) {
		inet_ntop(AF_INET, &d->saddr_v4, saddr, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &d->daddr_v4, daddr, INET_ADDRSTRLEN);

	} else if (d->family == AF_INET6) {
		inet_ntop(AF_INET6, &d->saddr_v6, saddr, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &d->daddr_v6, daddr, INET6_ADDRSTRLEN);
	}
	cJSON_AddNumberToObject(root, "timestamp", d->ts);
	cJSON_AddStringToObject(root, "interface", ifname);
	cJSON_AddStringToObject(root, "ip_proto", ipproto_mapping[d->ip_proto]);
	cJSON_AddNumberToObject(root, "pkt_type", d->pkt_type);
	cJSON_AddNumberToObject(root, "version", d->family);
	cJSON_AddStringToObject(root, "saddr", saddr);
	cJSON_AddNumberToObject(root, "saddr_port", ntohs(d->port16[0]));
	cJSON_AddStringToObject(root, "daddr", daddr);
	cJSON_AddNumberToObject(root, "daddr_port", ntohs(d->port16[1]));
	cJSON_AddNumberToObject(root, "len", d->len);
	char *json_str = cJSON_Print(root);
	cJSON_Delete(root);

	return json_str;
}

static void kafka_produce(const char *key, char *value)
{
	size_t key_len = strlen(key);
	size_t value_len = strlen(value);
	int err;

retry:
	err = rd_kafka_producev(
		/* Producer handle */
		producer,
		/* Topic name */
		RD_KAFKA_V_TOPIC(topic),
		/* Make a copy of the payload. */
		RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_COPY),
		/* Message key and length */
		RD_KAFKA_V_KEY(key, key_len),
		/* Message value and length */
		RD_KAFKA_V_VALUE(value, value_len),
		/* Per-Message opaque, provided in
                     * delivery report callback as
                     * msg_opaque. */
		RD_KAFKA_V_OPAQUE(NULL),
		/* End sentinel */
		RD_KAFKA_V_END);

	if (err != RD_KAFKA_RESP_ERR_NO_ERROR) {
		rd_kafka_flush(producer, 10 * 1000 /* wait for max 10 seconds */);
		printf("err = %d\n", err);
		goto retry;
	}

	// rd_kafka_flush(producer, 10 * 1000 /* wait for max 10 seconds */);
}
static int event_handler(void *ctx, void *data, size_t data_sz)
{
	const struct socket_event *d = data;
	if (d->pkt_type != PACKET_HOST && d->pkt_type != PACKET_OUTGOING)
		return 0;

	char *event_string = struct2json(data);
	if (event_string == NULL)
		return 0;
	kafka_produce("network", event_string);
	free(event_string);
	// if (d->family == AF_INET) {
	// 	inet_ntop(AF_INET, &d->saddr_v4, saddr, INET_ADDRSTRLEN);
	// 	inet_ntop(AF_INET, &d->daddr_v4, daddr, INET_ADDRSTRLEN);
	// 	printf("ipv4 ts: %lld: interface: %s  protocol: %s  %s:%d(src) -> %s:%d(dst)\tdata_len: %d.\n",
	// 	       d->ts, ifname, ipproto_mapping[d->ip_proto], saddr, ntohs(d->port16[0]),
	// 	       daddr, ntohs(d->port16[1]), d->len);

	// } else if (d->family == AF_INET6) {
	// 	inet_ntop(AF_INET6, &d->saddr_v6, saddr, INET6_ADDRSTRLEN);
	// 	inet_ntop(AF_INET6, &d->daddr_v6, daddr, INET6_ADDRSTRLEN);
	// 	printf("ipv6 ts: %lld: interface: %s  protocol: %s  %s:%d(src) -> %s:%d(dst)\tdata_len: %d.\n",
	// 	       d->ts, ifname, ipproto_mapping[d->ip_proto], saddr, ntohs(d->port16[0]),
	// 	       daddr, ntohs(d->port16[1]), d->len);
	// }
	return 0;
}

static int open_raw_sock(const char *name)
{
	struct sockaddr_ll sll;
	int sock;

	sock = socket(PF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC, htons(ETH_P_ALL));
	if (sock < 0) {
		fprintf(stderr, "Failed to create raw socket\n");
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = if_nametoindex(name);
	sll.sll_protocol = htons(ETH_P_ALL);
	if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		fprintf(stderr, "Failed to bind to %s: %s\n", name, strerror(errno));
		close(sock);
		return -1;
	}

	return sock;
}

/**
 * @brief Message delivery report callback.
 *
 * This callback is called exactly once per message, indicating if
 * the message was succesfully delivered
 * (rkmessage->err == RD_KAFKA_RESP_ERR_NO_ERROR) or permanently
 * failed delivery (rkmessage->err != RD_KAFKA_RESP_ERR_NO_ERROR).
 *
 * The callback is triggered from rd_kafka_poll() and executes on
 * the application's thread.
 */
static void dr_msg_cb(rd_kafka_t *rk, const rd_kafka_message_t *rkmessage, void *opaque)
{
	if (rkmessage->err)
		fprintf(stderr, "%% Message delivery failed: %s\n",
			rd_kafka_err2str(rkmessage->err));
	else
		fprintf(stderr,
			"%% Message delivered (%zd bytes, "
			"partition %" PRId32 ")\n",
			rkmessage->len, rkmessage->partition);

	/* The rkmessage is destroyed automatically by librdkafka */
}

rd_kafka_t *init_kafka()
{
	rd_kafka_t *rk; /* Producer instance handle */
	rd_kafka_conf_t *conf; /* Temporary configuration object */
	const char *brokers = "localhost:9192"; /* Argument: broker list */
	char errstr[512]; /* librdkafka API error reporting buffer */
	conf = rd_kafka_conf_new();
	if (rd_kafka_conf_set(conf, "bootstrap.servers", brokers, errstr, sizeof(errstr)) !=
	    RD_KAFKA_CONF_OK) {
		fprintf(stderr, "%s\n", errstr);
		return NULL;
	}
	/* Set the delivery report callback.
     * This callback will be called once per message to inform
     * the application if delivery succeeded or failed.
     * See dr_msg_cb() above.
     * The callback is only triggered from rd_kafka_poll() and
     * rd_kafka_flush(). */
	rd_kafka_conf_set_dr_msg_cb(conf, dr_msg_cb);
	rk = rd_kafka_new(RD_KAFKA_PRODUCER, conf, errstr, sizeof(errstr));
	if (!rk) {
		fprintf(stderr, "%% Failed to create new producer: %s\n", errstr);
		return NULL;
	}
	return rk;
}

int main(int argc, char **argv)
{
	//init_kafka
	producer = init_kafka();
	if (producer == NULL) {
		fprintf(stderr, "init kafka error \n");
		return 0;
	}

	//ebpf
	struct ring_buffer *rb = NULL;
	struct network_monitor_bpf *skel;
	int err, prog_fd, sock_fd;

	env.interface = "enp0s5"; //TODO:网卡名从参数中传进来

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	skel = network_monitor_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}
	printf("load success.\n");
	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), event_handler, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Create raw socket for localhost interface */
	sock_fd = open_raw_sock(env.interface);
	if (sock_fd < 0) {
		err = -2;
		fprintf(stderr, "Failed to open raw socket\n");
		goto cleanup;
	}

	prog_fd = bpf_program__fd(skel->progs.bpf_prog);
	if (setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd))) {
		err = -3;
		fprintf(stderr, "Failed to attach to raw socket\n");
		goto cleanup;
	}

	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	network_monitor_bpf__destroy(skel);
	rd_kafka_flush(producer, 1 * 1000 /* wait for max 10 seconds */);
	rd_kafka_destroy(producer);

	return 0;
}
