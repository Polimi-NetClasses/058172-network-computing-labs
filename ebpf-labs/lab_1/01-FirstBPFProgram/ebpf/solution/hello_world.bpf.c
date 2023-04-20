#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx) {
   bpf_printk("Hello World from BPF!");
   return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";