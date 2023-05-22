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

static __always_inline int parse_vlan_hdr(void *data, void *data_end, __u16 *nh_off, struct vlan_hdr **vlanhdr) {
   struct vlan_hdr *vlh = (struct vlan_hdr *)(data + *nh_off);
   int hdr_size = sizeof(*vlh);

   /* Byte-count bounds check; check if current pointer + size of header
    * is after data_end.
    */
   if ((void *)vlh + hdr_size > data_end)
      return -1;

   *nh_off += hdr_size;
   *vlanhdr = vlh;

   return vlh->h_vlan_encapsulated_proto; /* network-byte-order */
}

/* Pops the outermost VLAN tag off the packet. Returns 0 on
 * success or negative errno on failure.
 */
static __always_inline int vlan_tag_pop(struct xdp_md *ctx, struct ethhdr *eth, struct vlan_hdr *vlh, __u16 h_proto)
{
	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr eth_cpy;

	/* Make a copy of the outer Ethernet header before we cut it off */
	__builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

	/* Actually adjust the head pointer */
	if (bpf_xdp_adjust_head(ctx, (int)sizeof(*vlh)))
		return -1;

	/* Need to re-evaluate data *and* data_end and do new bounds checking
	 * after adjusting head
	 */
	eth = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	if ((void *)eth + sizeof(struct ethhdr) > data_end)
		return -1;

	/* Copy back the old Ethernet header and update the proto type */
	__builtin_memcpy(eth, &eth_cpy, sizeof(*eth));
	eth->h_proto = h_proto;

	return 0;
}

/* Pushes a new VLAN tag after the Ethernet header. Returns 0 on success,
 * -1 on failure.
 */
static __always_inline int vlan_tag_push(struct xdp_md *ctx, int vlid)
{
	void *data_end = (void *)(long)ctx->data_end;
   void *data = (void *)(long)ctx->data;
   struct ethhdr *eth = data;

	struct ethhdr eth_cpy;
	struct vlan_hdr *vlh;

   if ((void *)eth + sizeof(struct ethhdr) > data_end)
      return -1;

	/* First copy the original Ethernet header */
	__builtin_memcpy(&eth_cpy, eth, sizeof(struct ethhdr));

	/* Then add space in front of the packet */
	if (bpf_xdp_adjust_head(ctx, 0 - (int)sizeof(*vlh)))
		return -1;

	/* Need to re-evaluate data_end and data after head adjustment, and
	 * bounds check, even though we know there is enough space (as we
	 * increased it).
	 */
	data_end = (void *)(long)ctx->data_end;
	eth = (void *)(long)ctx->data;

	if ((void *)eth + sizeof(struct ethhdr) > data_end)
		return -1;

	/* Copy back Ethernet header in the right place, populate VLAN tag with
	 * ID and proto, and set outer Ethernet header to VLAN type.
	 */
	__builtin_memcpy(eth, &eth_cpy, sizeof(*eth));

	vlh = (void *)eth + sizeof(struct ethhdr);

	if ((void *)vlh + sizeof(struct vlan_hdr) > data_end)
		return -1;

	vlh->h_vlan_TCI = bpf_htons(vlid);
	vlh->h_vlan_encapsulated_proto = eth->h_proto;

	eth->h_proto = bpf_htons(ETH_P_8021Q);
	return 0;
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

      if (!proto_is_vlan(eth_type)) {
         bpf_printk("Packet is not VLAN tagged on interface 1");
         return XDP_DROP;
      }

      eth_type = parse_vlan_hdr(data, data_end, &nf_off, &vlh);
      if (eth_type < 0) {
         bpf_printk("Failed to parse VLAN header");
         return XDP_DROP;
      }

      vlan_id = bpf_ntohs(vlh->h_vlan_TCI) & VLAN_VID_MASK;
      if (vlan_id < 0) {
         bpf_printk("Failed to get VLAN ID");
         return XDP_ABORTED;
      }

      if (vlan_tag_pop(ctx, eth, vlh, eth_type) < 0) {
         bpf_printk("Failed to pop VLAN tag");
         return XDP_ABORTED;
      }

      bpf_printk("Popped VLAN tag with ID %d", vlan_id);

      bpf_printk("Redirect packet to interface 2 with ifindex: %d", vlan_handler_cfg.ifindex_if2);
      return bpf_redirect(vlan_handler_cfg.ifindex_if2, 0);
   } else if (ctx->ingress_ifindex == vlan_handler_cfg.ifindex_if2) {
      bpf_printk("Packet received from interface 2");

      if (proto_is_vlan(eth_type)) {
         bpf_printk("Packet is VLAN tagged on interface 2. DROP!");
         return XDP_DROP;
      }

      if (vlan_tag_push(ctx, vlan_handler_cfg.vlan_id) < 0) {
         bpf_printk("Failed to push VLAN tag");
         return XDP_ABORTED;
      }
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