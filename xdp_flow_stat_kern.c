#include <uapi/linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/in.h>
#include <uapi/linux/if_ether.h>
#include <linux/if_packet.h>
#include <uapi/linux/if_vlan.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/tcp.h>
 
#define KBUILD_MODNAME "flowstat"
#define FLOW_HASH_SIZE     33554432
#define INTERNAL static __attribute__((always_inline))
#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
//#define LOG(fmt, ...) bpf_printk(fmt "\n", ##__VA_ARGS__)

struct vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct Packet {
    struct  xdp_md* ctx;
    struct  ethhdr* ether;
    struct  iphdr* ip;
     __u16  vlan_id;
};


struct flow_t {
    __u32    ip_src;
    __u32    ip_dst;
    __u16    src_port;
    __u16    dst_port;
    __u16    vlan_id;
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
      .max_entries = FLOW_HASH_SIZE,
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
    flow.vlan_id = packet->vlan_id;
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
    flow.vlan_id = packet->vlan_id;
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
    flow.vlan_id = packet->vlan_id;
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
    u16 eth_type;
    u64 offset;

    void *data = (void *)(long)packet->ctx->data;
    void *data_end = (void *)(long)packet->ctx->data_end;

    packet->vlan_id = 1;
    offset = sizeof(*ether);

    if ((void *)ether + offset > data_end)
		return XDP_PASS;

    eth_type = ether->h_proto;

    //LOG("      ETH_TYPE %x", htons(eth_type)); // 0x0800
    
	/* Skip non 802.3 Ethertypes */
	if (unlikely(htons(eth_type) < ETH_P_802_3_MIN))
		return XDP_PASS;

	/* Handle VLAN tagged packet */
	if (htons(eth_type) == ETH_P_8021Q || htons(eth_type) == ETH_P_8021AD) {
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)ether + offset;
		offset += sizeof(*vlan_hdr);
		if ((void *)ether + offset > data_end)
			return XDP_PASS;
		eth_type = vlan_hdr->h_vlan_encapsulated_proto;

        packet->vlan_id = (bpf_ntohs(vlan_hdr->h_vlan_TCI) & VLAN_VID_MASK);
	}

    /* Handle double VLAN tagged packet */
    if (htons(eth_type) == ETH_P_8021Q || htons(eth_type) == ETH_P_8021AD) {
		struct vlan_hdr *vlan_hdr;

		vlan_hdr = (void *)ether + offset;
		offset += sizeof(*vlan_hdr);
        if ((void *)ether + offset > data_end)
			return XDP_PASS;
		eth_type = vlan_hdr->h_vlan_encapsulated_proto;

        packet->vlan_id = (bpf_ntohs(vlan_hdr->h_vlan_TCI) & VLAN_VID_MASK);
    }

    if (htons(eth_type) != ETH_P_IP) {
        return XDP_PASS;
    }
    
    struct iphdr* ip = (struct iphdr*)(data + offset);
    if ((void*)(ip + 1) > data_end) {
        return XDP_PASS; /* malformed packet */
    }
    packet->ip = ip;

    return process_ip(packet);
}

SEC("rx/in")
int track_in(struct xdp_md* ctx) {
    struct Packet packet;
    packet.ctx = ctx;

    struct ethhdr* ether = (struct ethhdr*)(void*)ctx->data;
    if ((void*)(ether + 1) > (void*)ctx->data_end) {
        return XDP_PASS;
    }

    packet.ether = ether;
    return process_ether(&packet);
}

SEC("rx/out")
int track_out(struct xdp_md* ctx) {
    struct Packet packet;
    packet.ctx = ctx;

    struct ethhdr* ether = (struct ethhdr*)(void*)ctx->data;
    if ((void*)(ether + 1) > (void*)ctx->data_end) {
        return XDP_PASS;
    }

    packet.ether = ether;
    return process_ether(&packet);
}

char _license[] SEC("license") = "GPL";

