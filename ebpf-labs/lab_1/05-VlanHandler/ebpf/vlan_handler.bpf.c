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

const volatile struct {
   int ifindex_if1;
   int ifindex_if2;
   __u16 vlan_id;
} vlan_handler_cfg = {};

/*
 *	struct vlan_hdr - vlan header
 *	@h_vlan_TCI: priority and VLAN ID
 *	@h_vlan_encapsulated_proto: packet type ID or len
 */
#define VLAN_VID_MASK		0x0fff /* VLAN Identifier */
struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

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

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return (h_proto == bpf_htons(ETH_P_8021Q) ||
		  h_proto == bpf_htons(ETH_P_8021AD));
}

/* TODO 3: Implement the parse vlan header function */
// static __always_inline int parse_vlan_hdr(void *data, void *data_end, __u16 *nh_off, struct vlan_hdr **vlanhdr) {
// }

/* TODO 5: Implement the vlan_tag_pop function */
/* Pops the outermost VLAN tag off the packet. Returns the popped VLAN ID on
 * success or negative errno on failure.
 */
static __always_inline int vlan_tag_pop(struct xdp_md *ctx, struct ethhdr *eth, struct vlan_hdr *vlh, __u16 h_proto) {
	/* Make a copy of the outer Ethernet header before we cut it off */

	/* Actually adjust the head pointer */

	/* Need to re-evaluate data *and* data_end and do new bounds checking
	 * after adjusting head
	 */

	/* Copy back the old Ethernet header and update the proto type */
}

/* TODO 8: Implement the vlan_tag_push function */
/* Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
 * -1 on failure.
 */
static __always_inline int vlan_tag_push(struct xdp_md *ctx, int vlid) {
   /* First copy the original Ethernet header */

   /* Then add space in front of the packet */

   /* Need to re-evaluate data_end and data after head adjustment, and
	 * bounds check, even though we know there is enough space (as we
	 * increased it).
	 */

   /* Copy back Ethernet header in the right place, populate VLAN tag with
	 * ID and proto, and set outer Ethernet header to VLAN type.
	 */
}

SEC("xdp")
int xdp_vlan_handler(struct xdp_md *ctx) {
   void *data_end = (void *)(long)ctx->data_end;
   void *data = (void *)(long)ctx->data;

   __u16 nf_off = 0;
   struct ethhdr *eth;
   struct vlan_hdr *vlh;
   int eth_type;
   int action = XDP_PASS;
   int vlan_id = 0;

   bpf_printk("Packet received from interface %d", ctx->ingress_ifindex);

   eth_type = parse_ethhdr(data, data_end, &nf_off, &eth);

   if (ctx->ingress_ifindex == vlan_handler_cfg.ifindex_if1) {
      bpf_printk("Packet received from interface 1");

      /* TODO 1: Check if protocol is VLAN 
       * If not, drop the packet
       */

      /* TODO 2: Parse VLAN header */

      /* TODO 4: Extract VLAN ID from packet */

      /* TODO 6: Pop VLAN tag */

      bpf_printk("Redirect packet to interface 2 with ifindex: %d", vlan_handler_cfg.ifindex_if2);
      return bpf_redirect(vlan_handler_cfg.ifindex_if2, 0);
   } else if (ctx->ingress_ifindex == vlan_handler_cfg.ifindex_if2) {
      bpf_printk("Packet received from interface 2");

      /* TODO 7: Check if the packet has VLAN tag 
       * If yes, drop the packet
       */

      /* TODO 9: Push the vlan tag.
       * Use the VLAN ID from the configuration
       */

      bpf_printk("Pushed VLAN tag with ID %d", vlan_handler_cfg.vlan_id);

      bpf_printk("Redirect packet to interface 1 with ifindex: %d", vlan_handler_cfg.ifindex_if1);
      return bpf_redirect(vlan_handler_cfg.ifindex_if1, 0);
   } else {
      bpf_printk("Packet received from unknown interface");
      return XDP_ABORTED;
   }

drop:
   return XDP_DROP;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";