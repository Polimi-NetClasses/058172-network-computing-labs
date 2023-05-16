#ifndef HHD_V2_UTILS_H_
#define HHD_V2_UTILS_H_

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
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

// Define devmap that will work as interface index lookup table
struct {
    __uint(type, BPF_MAP_TYPE_DEVMAP);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1024);
} devmap SEC(".maps");

struct ipv4_lookup_val {
    unsigned char dstMac[6];
    __u8 outPort;
};

struct src_mac_val {
    __u8 srcMac[6];
};

// Define HASH map that will work as IPv4 lookup table
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, struct ipv4_lookup_val);
    __uint(max_entries, 1024);
} ipv4_lookup_map SEC(".maps");

// Define array map that will tell us which source address to use
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u16);
    __type(value, struct src_mac_val);
    __uint(max_entries, 1024);
} src_mac_map SEC(".maps");

#endif // HHD_V2_UTILS_H_