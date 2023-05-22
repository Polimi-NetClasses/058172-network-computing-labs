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
struct datarec {
    __u64 rx_packets;
    __u64 rx_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, int);
    __type(value, struct datarec);
    __uint(max_entries, 1024);
} xdp_stats_map SEC(".maps");


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

static __always_inline int parse_iphdr(void *data, void *data_end, __u16 *nh_off, struct iphdr **iphdr) {
   struct iphdr *ip = data + *nh_off;
   int hdr_size;

   if ((void *)ip + sizeof(*ip) > data_end)
      return -1;
   
   hdr_size = ip->ihl * 4;

   /* Sanity check packet field is valid */
	if(hdr_size < sizeof(*ip))
		return -1;

   /* Variable-length IPv4 header, need to use byte-based arithmetic */
	if ((void *)ip + hdr_size > data_end)
		return -1;

   // It can also be written as:
   // if (data + *nh_off + hdr_size > data_end)
   //    return -1;

   *nh_off += hdr_size;
   *iphdr = ip;

   return ip->protocol;
}

static __always_inline int parse_icmphdr(void *data, void *data_end, __u16 *nh_off, struct icmphdr **icmphdr) {
   struct icmphdr *icmp = data + *nh_off;
   int hdr_size = sizeof(*icmp);

   if ((void *)icmp + hdr_size > data_end)
      return -1;

   *nh_off += hdr_size;
   *icmphdr = icmp;

   return icmp->type;
}

SEC("xdp")
int xdp_packet_parsing(struct xdp_md *ctx) {
   void *data_end = (void *)(long)ctx->data_end;
   void *data = (void *)(long)ctx->data;

   __u16 nf_off = 0;
   struct ethhdr *eth;
   int eth_type;
   struct datarec *rec;
   int key = 0;

   bpf_printk("Packet received");

   eth_type = parse_ethhdr(data, data_end, &nf_off, &eth);

   if (eth_type != bpf_ntohs(ETH_P_IP))
      goto pass;

   bpf_printk("Packet is IPv4");

   // Handle IPv4 and parse ICMP
   int ip_type;
   struct iphdr *iphdr;
   ip_type = parse_iphdr(data, data_end, &nf_off, &iphdr);

   if (ip_type != IPPROTO_ICMP)
      goto pass;

   bpf_printk("Packet is ICMP");

   int icmp_type;
   struct icmphdr *icmphdr;

   icmp_type = parse_icmphdr(data, data_end, &nf_off, &icmphdr);

   bpf_printk("Packet is ICMP type: %d", icmp_type);
   if (icmp_type != ICMP_ECHO)
      goto out;

   // Now let's check the sequence number
   __u16 seq = bpf_ntohs(icmphdr->un.echo.sequence);

   bpf_printk("Packet is ICMP ECHO with sequence number: %d", seq);

   // Check if sequence number is even
   if (seq % 2 == 0) {
      bpf_printk("Dropping packet with even sequence number: %d", seq);
      return XDP_DROP;
   }

out:
   bpf_printk("Packet passed");
   rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
   if (!rec) {
      return XDP_ABORTED;
   }

   __u64 bytes = data_end - data;
   __sync_fetch_and_add(&rec->rx_packets, 1);
   __sync_fetch_and_add(&rec->rx_bytes, bytes);

pass:
   return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";