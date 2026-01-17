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

char _license[] SEC("license") = "GPL";

struct os_config
{
    __u8 enabled;           // Spoofing enabled
    __u16 window_size;      // TCP Window Size
    __u8 ttl_value;         // Target TTL value
    __u8 df_flag;           // Don't Fragment flag
    __u8 options_len;       // Length of TCP options
    __u8 options[40];       // TCP options
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct os_config);
    __uint(max_entries, 1);
} config_map SEC(".maps");

static int __always_inline fetch_ethhdr(struct __sk_buff *skb, struct ethhdr **eth)
{
    *eth = (void *)(long)skb->data;
    return (void *)(*eth + 1) > (void *)(long)skb->data_end;
}

static int __always_inline fetch_iphdr(struct __sk_buff *skb, struct iphdr **ip)
{
    struct ethhdr *eth = (void *)(long)skb->data;
    *ip = (void *)(eth + 1);
    return (void *)(*ip + 1) > (void *)(long)skb->data_end;
}

static int __always_inline fetch_tcphdr(struct __sk_buff *skb, struct iphdr *ip, struct tcphdr **tcp)
{
    *tcp = (void *)ip + ip->ihl * 4;
    return (void *)(*tcp + 1) > (void *)(long)skb->data_end;
}

static int __always_inline spoof_ip(struct __sk_buff *skb, struct iphdr *ip, struct os_config *cfg)
{
    __u16 old_ttl = ip->ttl;
    __u16 new_ttl = cfg->ttl_value;
    ip->ttl = new_ttl;

    long err = bpf_l3_csum_replace(
        skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check),
        old_ttl, new_ttl, 2
    );
    if(err < 0) return err;

    return err;
}

static int __always_inline spoof_tcp(struct __sk_buff *skb, struct iphdr *ip, struct tcphdr *tcp, struct os_config *cfg)
{
    long err;
    __u32 old_buff, new_buff;

    // Only update SYN (+ ACK) packets for now
    if (!tcp->syn) return 0;

    // Update IP fields
    __u16 ip_hdr_len = ip->ihl * 4;
    __u16 packet_len = sizeof(struct ethhdr) + ip_hdr_len + sizeof(struct tcphdr) + cfg->options_len;
    __u16 old_tot_len = ip->tot_len;
    __u16 new_tot_len = bpf_htons(packet_len - sizeof(struct ethhdr));
    ip->tot_len = new_tot_len;

    // Update TCP fields
    tcp->window = bpf_htons(cfg->window_size);
    __u16 old_tcp_len = bpf_htons(tcp->doff * 4);
    __u16 new_tcp_len = bpf_htons(sizeof(struct tcphdr) + cfg->options_len);
    tcp->doff = (sizeof(struct tcphdr) + cfg->options_len) / 4;

    // Adjust packet length
    err = bpf_skb_change_tail(skb, packet_len, 0);
    if(err < 0) return err;

    // Required verifier check
    __u32 options_len = cfg->options_len;
    if(options_len == 0 || options_len > 40)
        return -1;

    // Update TCP options
    err = bpf_skb_store_bytes(
        skb, sizeof(struct ethhdr) + ip_hdr_len + sizeof(struct tcphdr),
        cfg->options, options_len, 0
    );
    if(err < 0) return err;

    // Recompute IP checksum
    err = bpf_l3_csum_replace(
        skb, sizeof(struct ethhdr) + offsetof(struct iphdr, check),
        old_tot_len, new_tot_len, 2
    );
    if(err < 0) return err;

    // Recompute TCP checksum (only pseudo-header, since we assume offloading)
    err = bpf_l4_csum_replace(
        skb, sizeof(struct ethhdr) + ip_hdr_len + offsetof(struct tcphdr, check),
        old_tcp_len, new_tcp_len, BPF_F_PSEUDO_HDR | 2
    );
    if(err < 0) return err;

    return 0;
}

SEC("tc_egress")
int spoof_packet(struct __sk_buff *skb)
{
    // Ensure the map contains data
    __u32 key = 0;
    struct os_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if(!cfg || !cfg->enabled) return TC_ACT_OK;

    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;

    // Fetch and validate the Ethernet header
    if(fetch_ethhdr(skb, &eth) != 0) return TC_ACT_SHOT;

    // We only handle IPv4 for now
    if(eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    // Fetch and validate the IP header
    if(fetch_iphdr(skb, &ip) != 0) return TC_ACT_SHOT;

    // Spoof fields in the IP header
    if(spoof_ip(skb, ip, cfg) < 0) return TC_ACT_SHOT;

    // Revalidate Ethernet and IP headers
    if(fetch_ethhdr(skb, &eth) != 0) return TC_ACT_SHOT;
    if(fetch_iphdr(skb, &ip) != 0) return TC_ACT_SHOT;

    // The following code only applies to TCP packets
    if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;

    // Fetch and validate the TCP header
    if(fetch_tcphdr(skb, ip, &tcp) != 0) return TC_ACT_SHOT;

    // Spoof fields in the TCP header
    if(spoof_tcp(skb, ip, tcp, cfg) < 0)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}
