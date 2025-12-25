// ============================================================================
// eBPF TC Egress Program (runs in kernel)
// ============================================================================

// #include "vmlinux.h"    // TODO Use it to enable CO-RE?

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


// Configuration map - userspace sets these values
struct os_config {
    __u32 enabled;         // Whether spoofing is enabled
    __u16 mss_value;       // Target MSS value
    __u16 window_size;     // TCP Window Size
    __u8 ttl_value;        // Target TTL value
    __u8 df_flag;          // Don't Fragment flag
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct os_config);
    __uint(max_entries, 1);
} config_map SEC(".maps");


// The annotation tells the eBPF loader that this function hooks into the TC egress path
SEC("tc_egress")
int spoof_syn_packet(struct __sk_buff *skb) {
    // Extract packet data from kernel socket buffer
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Prove to the eBPF verifier that memory access is safe
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return TC_ACT_OK;

    // Process only IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    // Prove to the eBPF verifier that memory access is safe
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return TC_ACT_OK;

    // Process only TCP packets
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    // Prove to the eBPF verifier that memory access is safe
    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void *)tcp + sizeof(*tcp) > data_end)
        return TC_ACT_OK;

    // Process only SYN packets 
    if (!tcp->syn || tcp->ack)
        return TC_ACT_OK;


    // Get configuration from map
    __u32 key = 0;
    struct os_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    // The verifier requires NULL checks after map lookups
    if (!cfg || !cfg->enabled)
        return TC_ACT_OK;
        

    // ============================================================================
    // READ ALL VALUES WHILE POINTERS ARE STILL VALID
    // (calling bpf_skb_store_bytes modifies skb and invalidates pointers)
    // ============================================================================
    __u32 ip_header_len = ip->ihl * 4;
    
    __u8 old_ttl = ip->ttl;
    __u16 old_window = tcp->window;

    // ============================================================================
    // CALCULATE ALL OFFSETS
    // ============================================================================
    // Values offsets
    __u32 ttl_off = sizeof(struct ethhdr) + offsetof(struct iphdr, ttl);
    __u32 window_off = sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, window);

    // Checksum offsets
    __u32 ip_csum_off = sizeof(struct ethhdr) + offsetof(struct iphdr, check);
    __u32 tcp_csum_off = sizeof(struct ethhdr) + ip_header_len + offsetof(struct tcphdr, check);

    // ============================================================================
    // UPDATE ALL VALUES AS PER CONFIGURATION
    // ============================================================================

    // TTL
    bpf_skb_store_bytes(skb, ttl_off, &cfg->ttl_value, 1, 0);
    bpf_l3_csum_replace(skb, ip_csum_off, (__u16)old_ttl, (__u16)cfg->ttl_value, 2);

    // Window size
    __u16 new_window = bpf_htons(cfg->window_size);
    bpf_skb_store_bytes(skb, window_off, &new_window, 2, 0);
    bpf_l4_csum_replace(skb, tcp_csum_off, old_window, new_window, 2);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
