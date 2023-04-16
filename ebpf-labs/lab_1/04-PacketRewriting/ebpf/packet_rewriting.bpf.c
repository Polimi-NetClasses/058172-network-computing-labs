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
/* TODO 10: Define map and structure to hold packet and byte counters */

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

/* TODO 3: Implement IP parsing function */
// static __always_inline int parse_iphdr(void *data, void *data_end, __u16 *nh_off, struct iphdr **iphdr) {
// }

/* TODO 5: Implement UDP protocol parsing function */
// static __always_inline int parse_udphdr(void *data, void *data_end, __u16 *nh_off, struct udphdr **udphdr) {
// }

/* TODO 7: Implement UDP protocol parsing function */
// static __always_inline int parse_tcphdr(void *data, void *data_end, __u16 *nh_off, struct tcphdr **tcphdr) {
// }

SEC("xdp")
int xdp_packet_rewriting(struct xdp_md *ctx) {
   void *data_end = (void *)(long)ctx->data_end;
   void *data = (void *)(long)ctx->data;

   __u16 nf_off = 0;
   struct ethhdr *eth;
   int eth_type;
   int action = XDP_PASS;

   bpf_printk("Packet received");

   eth_type = parse_ethhdr(data, data_end, &nf_off, &eth);

   if (eth_type != bpf_ntohs(ETH_P_IP)) {
      action = XDP_ABORTED;
      goto end;
   }

   bpf_printk("Packet is IPv4");

   // Handle IPv4 and parse TCP and UDP headers
   /* TODO 2: Parse IPv4 packet, pass all NON-ICMP packets */

   /* TODO 4: Parse UDP packet 
    * Descrease UDP destination port by 1
   */

   /* TODO 6: Parse TCP packet 
    * Descrease TCP destination port by 1
   */

   /* TODO 8: All the non UDP/TCP packets shold return XDP_ABORTED */

out:
   bpf_printk("Packet passed");
   /* TODO 9: Count packets and bytes and store them into an ARRAY map */

end:
   return action;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";