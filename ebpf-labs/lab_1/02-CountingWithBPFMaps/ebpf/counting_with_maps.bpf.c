#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <stddef.h>
#include <stdint.h>

/* This is the data record stored in the map */
struct datarec {
	/* TODO 1: Add packet counter */
	/* TODO 2: Add byte counter */
};

/* TODO 3: Define your map here */

SEC("xdp")
int xdp_prog_map(struct xdp_md *ctx) {
   void *data_end = (void *)(long)ctx->data_end;
   void *data = (void *)(long)ctx->data;

   struct datarec *rec;
   int key = 0;

   /* TODO 4: Lookup the map to get the datarec pointer 
    * Remember to add the check if it is NULL
    * return XDP_ABORTED if it is NULL
    */

   /* TODO 5: Update the packet counter */
   /* TODO 6: Update the byte counter */

   return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";