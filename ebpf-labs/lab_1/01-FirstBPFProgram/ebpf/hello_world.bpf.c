#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog_simple(struct xdp_md *ctx) {
   //TODO: Implement the BPF program
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";