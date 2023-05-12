#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>
#include <stdint.h>

const volatile struct {
   int ifindex_if1;
   int ifindex_if2;
   int ifindex_if3;
   int ifindex_if4;
} hhdv1_cfg = {};


/* TODO 5: Define the struct with of the map value */

/* TODO 4: Define the map that contains the threshold.
 * The key of the map is the source IP address and the value is a struct 
 * containing the threshold and the number of packets received.
 */

/* This map is used to associate the destination IP to port number */
struct {
   __uint(type, BPF_MAP_TYPE_HASH);
   __type(key, __u32);
   __type(value, __u32);
   __uint(max_entries, 16);
} ip_to_port SEC(".maps");

static __always_inline int parse_ethhdr(void *data, void *data_end, __u16 *nh_off, struct ethhdr **ethhdr) {
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

/* TODO 3: Implement the parse ipv4 header function */
// static __always_inline int parse_iphdr(void *data, void *data_end, __u16 *nh_off, struct iphdr **iphdr) {
// }

SEC("xdp")
int xdp_hhdv1(struct xdp_md *ctx) {
   void *data_end = (void *)(long)ctx->data_end;
   void *data = (void *)(long)ctx->data;

   __u16 nf_off = 0;
   struct ethhdr *eth;
   //struct iphdr *ip;
   int eth_type, ip_type;
   int action = XDP_PASS;

   bpf_printk("Packet received from interface %d", ctx->ingress_ifindex);

   eth_type = parse_ethhdr(data, data_end, &nf_off, &eth);

   /* TODO 1: Check if the packet is IPv4, if not drop the packet */

   /* TODO 2: Parse the IPv4 header */

   if (ctx->ingress_ifindex != hhdv1_cfg.ifindex_if4) {
      /* TODO 6: Lookup the map to get the threshold value 
       * If no threshold is set for the IP, drop the packet
      */

      /* TODO 7: Check if the # of packets received is over the threshold 
       * If so, drop the packet
      */

      /* TODO 8: Forward packet to interface 4 (ifindex_if4) */
   } else {
      bpf_printk("Packet received from interface %d", ctx->ingress_ifindex);

      /* TODO 9: Check if destination IP is in the map
       * The key of the map is the destination IP address (in network byte order)
       * If not, drop the packet
       * If so, forward the packet to the port associated to the IP
       * E.g., if the port is 1, forward the packet to interface 1 (ifindex_if1)
      */
   }

drop:
   return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";