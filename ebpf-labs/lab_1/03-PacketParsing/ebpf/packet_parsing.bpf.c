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

/* This is the data record stored in the map */
/* TODO 9: Define map and structure to hold packet and byte counters */

static __always_inline int parse_ethhdr(void *data, void *data_end, __u16 *nh_off, struct ethhdr **ethhdr) {
   struct ethhdr *eth = (struct ethhdr *)data;
   int hdr_size = sizeof(*eth);

   /* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
   /* TODO 1: Fix bound checking errors */
   if (data + 1 > data_end)
      return -1;

   *nh_off += hdr_size;
   *ethhdr = eth;

   return eth->h_proto; /* network-byte-order */
}

/* TODO 3: Implement IP parsing function */
// static __always_inline int parse_iphdr(void *data, void *data_end, __u16 *nh_off, struct iphdr **iphdr) {
// }

/* TODO 5: Implement ICMP parsing function */
// static __always_inline int parse_icmphdr(void *data, void *data_end, __u16 *nh_off, struct icmphdr **icmphdr) {
// }

SEC("xdp")
int xdp_packet_parsing(struct xdp_md *ctx) {
   void *data_end = (void *)(long)ctx->data_end;
   void *data = (void *)(long)ctx->data;

   __u16 nf_off = 0;
   struct ethhdr *eth;
   int eth_type;

   bpf_printk("Packet received");

   eth_type = parse_ethhdr(data, data_end, &nf_off, &eth);

   if (eth_type != bpf_ntohs(ETH_P_IP))
      goto pass;

   bpf_printk("Packet is IPv4");

   /* TODO 2: Parse IPv4 packet, pass all NON-ICMP packets */

   /* TODO 4: Parse ICMP packet, pass all NON-ICMP ECHO packets */
   /* ICMP EHCO REPLY packets should goto pass */

   /* TODO 6: Retrieve sequence number from ICMP packet */

   /* TODO 7: Check if sequence number is even 
    * If even, drop packet
    * If odd, goto out, where packets and bytes are counted
    */

out:
   bpf_printk("Packet passed");
   /* TODO 8: Count packets and bytes and store them into an ARRAY map */

pass:
   return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";