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

// IP checksum calculation
static __always_inline __u16 ip_fast_csum(void *iph, __u32 ihl, void* data_end)
{
    // ONLY WORKS FOR SYN PACKETS WITH NO OPTIONS (20 BYTES)
    __u16 *buf = (__u16 *)iph;
    __u64 csum = 0;
    
    // Hardcoded unroll for 20 bytes (10 words)
    csum += buf[0];
    csum += buf[1];
    csum += buf[2];
    csum += buf[3];
    csum += buf[4];
    csum += buf[5];
    csum += buf[6];
    csum += buf[7];
    csum += buf[8];
    csum += buf[9];
    
    // Fold
    csum = (csum & 0xffffffff) + (csum >> 32);
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return ~(__u16)csum;
    /*
    __u16 *buf = (__u16 *)iph;
    __u64 csum = 0;
    
    #pragma unroll
    for (int i = 0; i < 15; i++) {  // Max 60 bytes = 15 words
        // Only access if within logical header length
        if (i < ihl) {
            // Only access if within physical packet bounds
            if ((void *)(buf + i + 1) <= data_end) {
                csum += buf[i];
            }
        }
    }
    
    // Fold 64 -> 16
    csum = (csum & 0xffffffff) + (csum >> 32);
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16); // Double fold for safety
    
    return ~(__u16)csum;
    */
}

// TCP checksum (pseudo-header + TCP header + data)
static __always_inline __u16 tcp_checksum(struct iphdr *iph, struct tcphdr *tcph, 
                                          void *data_end, __u16 tcp_len)
{
    __u32 csum = 0;
    
    // Pseudo-header
    __u32 saddr = iph->saddr;
    __u32 daddr = iph->daddr;
    
    csum += saddr & 0xFFFF;
    csum += saddr >> 16;
    csum += daddr & 0xFFFF;
    csum += daddr >> 16;
    csum += bpf_htons((__u16)IPPROTO_TCP);
    csum += bpf_htons(tcp_len);
    
    // TCP header + data (as 16-bit words)
    __u16 *buf = (__u16 *)tcph;
    
    #pragma unroll
    for (int i = 0; i < 30; i++) {  // Max 60 bytes = 30 words
        if ((void *)(buf + i + 1) > data_end)
            break;
        if (i != 8)  // Skip checksum field itself (offset 16, word 8)
            csum += buf[i];
    }
    
    // Fold to 16 bits
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    
    return ~(__u16)csum;
}


// The annotation tells the eBPF loader that this function hooks into the TC egress path
SEC("tc_egress")
int spoof_syn_packet(struct __sk_buff *skb) {
    // Extract packet data from kernel socket buffer
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    // Prove to the eBPF verifier that memory access is safe
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) return TC_ACT_OK;

    // Process only IPv4 packets
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    // Prove to the eBPF verifier that memory access is safe
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_OK;

    // IP header length
    __u32 ip_hdr_len = ip->ihl * 4;
    if (ip_hdr_len < 20 || ip_hdr_len > 60) return TC_ACT_OK;

    // Process only TCP packets
    if (ip->protocol != IPPROTO_TCP) return TC_ACT_OK;

    // Prove to the eBPF verifier that memory access is safe
    struct tcphdr *tcp = (void *)ip + ip_hdr_len;
    if ((void *)tcp + sizeof(*tcp) > data_end) return TC_ACT_OK;

    // Process only SYN packets 
    if (!tcp->syn || tcp->ack) return TC_ACT_OK;

    // Get configuration from map
    __u32 key = 0;
    struct os_config *cfg = bpf_map_lookup_elem(&config_map, &key);
    // The verifier requires NULL checks after map lookups
    if (!cfg || !cfg->enabled)
        return TC_ACT_OK;

    // =====================================================================
    // 1. PREPARE FOR RESIZE
    // =====================================================================
    // Calculate dimensions
    __u8 old_tcp_hdr_len = tcp->doff * 4;
    __u8 old_options_len = old_tcp_hdr_len - 20;
    __u8 new_options_len = 4; // MSS (4 bytes)

    // Calculate delta
    int len_diff = (int)new_options_len - (int)old_options_len;

    // Define offsets
    __u32 ip_offset = sizeof(struct ethhdr);
    __u32 tcp_offset = ip_offset + ip_hdr_len;

    // Save the TCP fixed header (20 bytes) to stack
    struct tcphdr tcp_fixed_save;
    if (bpf_skb_load_bytes(skb, tcp_offset, &tcp_fixed_save, sizeof(tcp_fixed_save)) < 0) {
        return TC_ACT_SHOT;
    }

    // =====================================================================
    // 2. ADJUST ROOM (Create/Remove Gap)
    // =====================================================================
    // BPF_ADJ_ROOM_NET: Inserts/removes bytes AFTER IP header (Offset 0 of L4)
    if (bpf_skb_adjust_room(skb, len_diff, BPF_ADJ_ROOM_NET, BPF_F_ADJ_ROOM_FIXED_GSO) != 0) {
        return TC_ACT_SHOT;
    }

    // =====================================================================
    // 3. RESTORE HEADERS & INJECT OPTIONS
    // =====================================================================
    // Move the TCP fixed header BACK to the start of the L4 region
    if (bpf_skb_store_bytes(skb, tcp_offset, &tcp_fixed_save, sizeof(tcp_fixed_save), 0) < 0) {
        return TC_ACT_SHOT;
    }

    // Write our NEW Options immediately after the TCP fixed header
    // Offset = tcp_offset + 20 bytes
    __u8 mss_opt[4] = {
        0x02, 0x04,                  // Kind=2 (MSS), Len=4
        cfg->mss_value >> 8,         // Value High
        cfg->mss_value & 0xFF        // Value Low
    };

    if (bpf_skb_store_bytes(skb, tcp_offset + 20, mss_opt, sizeof(mss_opt), 0) < 0) {
        return TC_ACT_SHOT;
    }

    // =====================================================================
    // 4. UPDATE FIELDS AS PER CONFIGURATION
    // =====================================================================
    // Update TCP Data Offset (doff) to reflect new size (24 bytes = 6 words)
    __u8 new_doff = (6 << 4); 
    if (bpf_skb_store_bytes(skb, tcp_offset + 12, &new_doff, 1, 0) < 0) {
        return TC_ACT_SHOT;
    }

    // Update TTL (IP header with offset 8)
    if (bpf_skb_store_bytes(skb, ip_offset + 8, &cfg->ttl_value, 1, 0) < 0) {
        return TC_ACT_SHOT;
    }

    // Update Window size
    __u16 new_window = bpf_htons(cfg->window_size);
    if (bpf_skb_store_bytes(skb, tcp_offset + 14, &new_window, 2, 0) < 0) {
        return TC_ACT_SHOT;
    }

    // Update total length in IP header
    __u32 tot_len_offset = ip_offset + offsetof(struct iphdr, tot_len);
    __u16 new_ip_len = bpf_htons(ip_hdr_len + 20 + new_options_len);    // Network byte order
    if (bpf_skb_store_bytes(skb, tot_len_offset, &new_ip_len, 2, 0) < 0) {
        return TC_ACT_SHOT;
    }

    // =====================================================================
    // RECALCULATE CHECKSUMS
    // ===================================================================== 
    // Zero IP Checksum
    __u16 zero = 0;
    __u32 ip_csum_offset = sizeof(struct ethhdr) + offsetof(struct iphdr, check);
    if (bpf_skb_store_bytes(skb, ip_csum_offset, &zero, 2, 0) < 0) {
        return TC_ACT_SHOT;
    }
    
    // Adjust invalidated pointers after skb adjustment
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    ip = data + sizeof(struct ethhdr);
    if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_SHOT;
    
    // Bounds check IHL
    __u32 ihl = ip->ihl;
    if (ihl < 5 || ihl > 15) return TC_ACT_SHOT;

    // Calculate IP Checksum
    __u16 ip_csum = ip_fast_csum((__u8 *)ip, ip->ihl, data_end);
    
    // Store IP Checksum
    if (bpf_skb_store_bytes(skb, ip_csum_offset, &ip_csum, 2, 0) < 0) {
        return TC_ACT_SHOT;
    }

    // Zero TCP Checksum
    if (bpf_skb_store_bytes(skb, tcp_offset + 16, &zero, 2, 0) < 0) {
        return TC_ACT_SHOT;
    }

    // Adjust invalidated pointers after skb adjustment
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    ip = data + sizeof(struct ethhdr);
    if ((void *)ip + sizeof(*ip) > data_end) return TC_ACT_SHOT;
    tcp = data + tcp_offset;
    if ((void *)tcp + sizeof(*tcp) > data_end) return TC_ACT_SHOT;

    // Calculate new lengths
    new_ip_len = bpf_ntohs(ip->tot_len);
    __u16 new_tcp_len = new_ip_len - ip_hdr_len;
    
    // Calculate TCP Checksum
    __u16 tcp_csum = tcp_checksum(ip, tcp, data_end, new_tcp_len);
    
    // Store TCP Checksum
    if (bpf_skb_store_bytes(skb, tcp_offset + 16, &tcp_csum, 2, 0) < 0) {
        return TC_ACT_SHOT;
    }
    
    // The modified packet is accepted and transmitted
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
