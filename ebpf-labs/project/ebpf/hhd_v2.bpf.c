#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>
#include <stdint.h>

#include "fasthash.h"
#include "hhd_v2_utils.bpf.h"
#include "jhash.h"

#define BLOOM_FILTER_ENTRIES 4096
#define FASTHASH_SEED 0xdeadbeef
#define JHASH_SEED 0x2d31e867

const volatile struct { 
    __u64 threshold; 
} hhd_v2_cfg = {};

/* TODO 6: Define a C struct for the 5-tuple
 * (source IP, destination IP, source port, destination port, protocol).
 */

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, BLOOM_FILTER_ENTRIES);
} bloom_filter_map SEC(".maps");

static __always_inline int parse_ethhdr(void *data, void *data_end, __u16 *nh_off,
                                        struct ethhdr **ethhdr) {
    struct ethhdr *eth = (struct ethhdr *)data;
    int hdr_size = sizeof(*eth);

    /* Byte-count bounds check; check if current pointer + size of header
     * is after data_end.
     */
    if ((void *)eth + hdr_size > data_end)
        return -1;

    *nh_off += hdr_size;
    *ethhdr = eth;

    return eth->h_proto; /* network-byte-order */
}

static __always_inline int parse_iphdr(void *data, void *data_end, __u16 *nh_off,
                                       struct iphdr **iphdr) {
    /* TODO 4: Implement the parse_iphdr header function */

    /* Instead of returning 0, return the IP protocol value contained in the IPv4
     * header */
    return 0;
}

static __always_inline int parse_tcphdr(void *data, void *data_end, __u16 *nh_off,
                                        struct tcphdr **tcphdr) {
    /* TODO 9: Implement the parse_tcphdr header function */

    /* TODO 10: Make sure you check the actual size of the TCP header
     * The TCP header size is stored in the doff field, which is a 4-bit field
     * that stores the number of 32-bit words in the TCP header.
     * The minimum size of the TCP header is 5 words (20 bytes) and the maximum
     * is 15 words (60 bytes).
     */

    /* Instead of returning 0, return the actual size of the TCP header */
    return 0;
}

static __always_inline int parse_udphdr(void *data, void *data_end, __u16 *nh_off,
                                        struct udphdr **udphdr) {
    /* TODO 12: Implement the parse_udphdr header function */

    /* Instead of returning 0, return the actual size of the UDP header */
    return 0;
}

SEC("xdp")
int xdp_hhd_v2(struct xdp_md *ctx) {
    __u16 nf_off = 0;
    struct ethhdr *eth;
    __u16 eth_type;
    struct ipv4_lookup_val *val;
    struct src_mac_val *src_mac_val;
    __u16 src_mac_key;
    int action = XDP_PASS;
    __u32 ipv4_lookup_map_key;
    // struct iphdr *ip;
    // struct tcphdr *tcp;
    // struct udphdr *udp;

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    bpf_printk("Packet received from interface (ifindex) %d", ctx->ingress_ifindex);

    eth_type = parse_ethhdr(data, data_end, &nf_off, &eth);

    if (data + sizeof(struct ethhdr) > data_end) {
        bpf_printk("Packet is not a valid Ethernet packet");
        return XDP_DROP;
    }

    /* TODO 1: Check if the packet is ARP.
     * If it is, return XDP_PASS.
     */

    /* TODO 2: Check if the packet is IPv4.
     * If it is, continue with the program.
     * If it is not, return XDP_DROP.
     */

    /* TODO 3: Parse the IPv4 header.
     * If the packet is not a valid IPv4 packet, return XDP_DROP.
     */

    /* TODO 5: Define a C struct for the 5-tuple
     * (source IP, destination IP, source port, destination port, protocol).
     * Fill the struct with the values from the packet.
     */

    /* TODO 7: Check if the packet is TCP or UDP
     * If it is, fill the 5-tuple struct with the values from the packet.
     * If it is not, goto forward.
     */

    /* TODO 8: If the packet is TCP, parse the TCP header */

    /* TODO 11: If the packet is UDP, parse the UDP header */

    /* TODO 13: Let's apply the heavy hitter detection algorithm
     * You can use two different hash functions for this.
     * You can use the jhash function and the fasthash function.
     * Both functions are already imported and ready to use.
     * The first parameter of both functions is the data to hash.
     * The second parameter is the size of the data to hash.
     * The third parameter is the seed to use for the hash function.
     * You can use the define values FASTHASH_SEED and JHASH_SEED for the seed.
     */

    /* TODO 14: Check if the values from the bloom filter are above the threshold
     * If they are, the packet is part of a DDoS attack, so drop it.
     * If they are not, the packet is not part of a DDoS attack, so let it pass
     * (goto forward). You can use the hhd_v2_cfg.threshold variable for the
     * threshold value.
     */

forward:
    /* TODO 15: Copy inside the ipv4_lookup_map_key variable the destination IP
     * address of the packet The value should be in network byte order. E.g.,
     * ipv4_lookup_map_key = flow.daddr;
     */

    /* From here on, you don't need to modify anything
     * The following code will check if the destination IP is in the hash map.
     * If it is, it will forward the packet to the correct interface.
     * If it is not, it will drop the packet.
     */

    /* In this case the packet is allowed to pass, let's see if the hash map
     * contains the dst ip */
    val = bpf_map_lookup_elem(&ipv4_lookup_map, &ipv4_lookup_map_key);

    if (!val) {
        bpf_printk("Error looking up destination IP in map");
        action = XDP_ABORTED;
        goto out;
    }

    if (val->outPort < 1 || val->outPort > 4) {
        bpf_printk("Error looking up destination port in map");
        action = XDP_ABORTED;
        goto out;
    }

    src_mac_key = val->outPort;
    src_mac_val = bpf_map_lookup_elem(&src_mac_map, &src_mac_key);

    if (!src_mac_val) {
        bpf_printk("Error looking up source MAC in map with key: %d", src_mac_key);
        action = XDP_ABORTED;
        goto out;
    }

    __builtin_memcpy(eth->h_source, src_mac_val->srcMac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, val->dstMac, ETH_ALEN);

    bpf_printk("Packet forwarded to interface %d", val->outPort);

    action = bpf_redirect_map(&devmap, val->outPort, 0);

    if (action != XDP_REDIRECT) {
        bpf_printk("Error redirecting packet");
        action = XDP_ABORTED;
        goto out;
    }

out:
    return action;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";