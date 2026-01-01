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
    __u16 window_size;      // TCP Window Size
    __u8 ttl_value;         // Target TTL value
    __u8 df_flag;           // Don't Fragment flag
    __u8 options_size;      // Size of TCP options
    __u8 options[40];       // TCP options
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct os_config);
    __uint(max_entries, 1);
} config_map SEC(".maps");

static int __always_inline fetch_eth(struct __sk_buff *skb, struct ethhdr **eth)
{
    *eth = (void *)(long)skb->data;
    return (void *)(*eth + 1) > (void *)(long)skb->data_end;
}

static int __always_inline fetch_ip(struct __sk_buff *skb, struct ethhdr *eth, struct iphdr **ip)
{
    *ip = (void *)(eth + 1);
    return (void *)(*ip + 1) > (void *)(long)skb->data_end;
}

static int __always_inline fetch_tcp(struct __sk_buff *skb, struct iphdr *ip, struct tcphdr **tcp)
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

    return err;
}

static int __always_inline spoof_tcp(struct __sk_buff *skb, struct iphdr *ip, struct tcphdr *tcp, struct os_config *cfg)
{
    __u16 old_window = tcp->window;
    __u16 new_window = bpf_htons(cfg->window_size);
    tcp->window = new_window;

    long err = bpf_l4_csum_replace(
        skb, sizeof(struct ethhdr) + ip->ihl * 4 + offsetof(struct tcphdr, check),
        old_window, new_window, 2
    );

    return err;
}

SEC("tc_egress")
int spoof_packet(struct __sk_buff *skb)
{
    // Ensure the map contains data
    __u32 key = 0;
    struct os_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    if(!cfg) return TC_ACT_OK;

    struct ethhdr *eth;
    struct iphdr *ip;
    struct tcphdr *tcp;

    // Fetch and validate the Ethernet header
    if(fetch_eth(skb, &eth) != 0) return TC_ACT_SHOT;

    // We only handle IPv4 for now
    if(eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    // Fetch and validate the IP header
    if(fetch_ip(skb, eth, &ip) != 0) return TC_ACT_SHOT;

    // Spoof fields in the IP header
    if(spoof_ip(skb, ip, cfg) < 0) return TC_ACT_SHOT;

    // Revalidate Ethernet and IP headers
    if(fetch_eth(skb, &eth) != 0) return TC_ACT_SHOT;
    if(fetch_ip(skb, eth, &ip) != 0) return TC_ACT_SHOT;

    // The following code only applies to TCP packets
    if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;

    // Fetch and validate the TCP header
    if(fetch_tcp(skb, ip, &tcp) != 0) return TC_ACT_SHOT;

    // We only handle SYN packets for now
    if (!tcp->syn || tcp->ack) return TC_ACT_OK;

    // Spoof fields in the TCP header
    if(spoof_tcp(skb, ip, tcp, cfg) < 0)
        return TC_ACT_SHOT;

    return TC_ACT_OK;
}