#include <uapi/linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <uapi/linux/if_ether.h>
#include <linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/tcp.h>

#define CONNTRACK_HASH_SIZE     16777216

/* eBPF requires all functions to be inlined */
#define INTERNAL static __attribute__((always_inline))


struct Packet {
    /* For verification to for passing to BPF helpers. */
    struct xdp_md* ctx;

    /* Layer headers (may be NULL on lower stages) */
    struct ethhdr* ether;
    struct iphdr* ip;
};

// Если протокол ICMP ставим порты 0, 0, protocol = IPPROTO_ICMP
struct flow_t {
    __u32    ip_src;
    __u32    ip_dst;
    __u16    src_port;
    __u16    dst_port;
    __u8     protocol;
};

struct counters_t {
        __u64 total_bytes;
        __u64 total_packets;
};


struct bpf_map_def SEC("maps") m_flowtable = {
      .type        = BPF_MAP_TYPE_LRU_HASH,
      .key_size    = sizeof(struct flow_t),
      .value_size  = sizeof(struct counters_t),
      .max_entries = CONNTRACK_HASH_SIZE,
      .map_flags   = 0
};


INTERNAL void
update_stat(struct Packet* packet, struct flow_t flow) {

    __u16 payload_len = ntohs(packet->ip->tot_len);   
    struct counters_t* counter = NULL;
    
    counter = bpf_map_lookup_elem(&m_flowtable, &flow);

    if (counter) {
		__sync_fetch_and_add(&counter->total_bytes, payload_len);
        __sync_fetch_and_add(&counter->total_packets, 1);
	} else {
		struct counters_t val = {payload_len, 1};
		bpf_map_update_elem(&m_flowtable, &flow, &val, BPF_ANY);
	}
}


INTERNAL void
process_tcp(struct Packet* packet) {
    
    struct iphdr* ip = packet->ip;
    
    struct tcphdr* tcp = (struct tcphdr*)(ip + 1);
    if ((void*)(tcp + 1) > (void*)packet->ctx->data_end) {
        return; /* malformed packet */
    }

    struct flow_t flow;
    flow.ip_src = bpf_ntohl(ip->saddr);
    flow.ip_dst = bpf_ntohl(ip->daddr);
    flow.src_port = bpf_ntohs(tcp->source);
    flow.dst_port = bpf_ntohs(tcp->dest);
    flow.protocol = ip->protocol;

    update_stat(packet, flow);

}


INTERNAL void
process_udp(struct Packet* packet) {
    
    struct iphdr* ip = packet->ip;
    
    struct udphdr* udp = (struct udphdr*)(ip + 1);
    if ((void*)(udp + 1) > (void*)packet->ctx->data_end) {
        return; /* malformed packet */
    }
    
    struct flow_t flow;
    flow.ip_src = bpf_ntohl(ip->saddr);
    flow.ip_dst = bpf_ntohl(ip->daddr);
    flow.src_port = bpf_ntohs(udp->source);
    flow.dst_port = bpf_ntohs(udp->dest);
    flow.protocol = ip->protocol;

    update_stat(packet, flow);
}


INTERNAL void
process_icmp(struct Packet* packet) {
    
    struct iphdr* ip = packet->ip;
    
    struct flow_t flow;
    flow.ip_src = bpf_ntohl(ip->saddr);
    flow.ip_dst = bpf_ntohl(ip->daddr);
    flow.src_port = 0;
    flow.dst_port = 0;
    flow.protocol = ip->protocol;

    update_stat(packet, flow);

}


INTERNAL int
process_ip(struct Packet* packet) {

    struct iphdr* ip = packet->ip;  

    switch (ip->protocol) {
	case IPPROTO_ICMP:
		process_icmp(packet);
		break;
	case IPPROTO_TCP:
		process_tcp(packet);
		break;
	case IPPROTO_UDP:
		process_udp(packet);
		break;
	default:
		break;
	}

    return XDP_PASS;
}

INTERNAL int
process_ether(struct Packet* packet) {
    struct ethhdr* ether = packet->ether;


    if (ether->h_proto != bpf_ntohs(ETH_P_IP)) {
        return XDP_PASS;
    }

    struct iphdr* ip = (struct iphdr*)(ether + 1);
    if ((void*)(ip + 1) > (void*)packet->ctx->data_end) {
        return XDP_PASS; /* malformed packet */
    }
    packet->ip = ip;
    return process_ip(packet);
}

SEC("prog")
int xdp_main(struct xdp_md* ctx) {
    struct Packet packet;
    packet.ctx = ctx;

    struct ethhdr* ether = (struct ethhdr*)(void*)ctx->data;
    if ((void*)(ether + 1) > (void*)ctx->data_end) {
        return XDP_PASS; /* what are you? */
    }

    packet.ether = ether;
    return process_ether(&packet);
}

char _license[] SEC("license") = "GPL";

