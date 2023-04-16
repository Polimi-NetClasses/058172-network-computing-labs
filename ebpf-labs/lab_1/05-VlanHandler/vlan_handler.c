// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <assert.h>
#include <linux/if_link.h>

#include <argparse.h>
#include <net/if.h>

#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <signal.h>

#include "log.h"

// Include skeleton file
#include "vlan_handler.skel.h"

static int ifindex_iface1 = 0;
static int ifindex_iface2 = 0;
static __u32 xdp_flags = 0;

static const char *const usages[] = {
    "vlan_handler [options] [[--] args]",
    "vlan_handler [options]",
    NULL,
};

static void cleanup_ifaces() {
    __u32 curr_prog_id = 0;

    if (ifindex_iface1 != 0) {
        if (!bpf_xdp_query_id(ifindex_iface1, xdp_flags, &curr_prog_id)) {
            if (curr_prog_id) {
                bpf_xdp_detach(ifindex_iface1, xdp_flags, NULL);
                log_trace("Detached XDP program from interface %d", ifindex_iface1);
            }
        }
    }

    if (ifindex_iface2 != 0) {
        if (!bpf_xdp_query_id(ifindex_iface2, xdp_flags, &curr_prog_id)) {
            if (curr_prog_id) {
                bpf_xdp_detach(ifindex_iface2, xdp_flags, NULL);
                log_trace("Detached XDP program from interface %d", ifindex_iface2);
            }
        }
    }
}

void sigint_handler(int sig_no) {
    log_debug("Closing program...");
    cleanup_ifaces();
    exit(0);
}

int main(int argc, const char **argv) {
    struct vlan_handler_bpf *skel = NULL;
    int err;
    const char *iface1 = NULL;
    const char *iface2 = NULL;

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_STRING('1', "iface1", &iface1, "1st interface where to attach the BPF program", NULL, 0, 0),
        OPT_STRING('2', "iface2", &iface2, "2nd interface where to attach the BPF program", NULL, 0, 0),
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(&argparse, "\n[Exercise 1] This software attaches an XDP program to the interface specified in the input parameter", 
    "\nIf '-p' argument is specified, the interface will be put in promiscuous mode");
    argc = argparse_parse(&argparse, argc, argv);

    if (iface1 != NULL) {
        log_info("XDP program will be attached to %s interface", iface1);
        ifindex_iface1 = if_nametoindex(iface1);
        if (!ifindex_iface1) {
            log_fatal("Error while retrieving the ifindex of %s", iface1);
            exit(1);
        } else {
            log_info("Got ifindex for iface: %s, which is %d", iface1, ifindex_iface1);
        }
    } else {
        log_error("Error, you must specify the interface where to attach the XDP program");
        exit(1);
    }

    if (iface2 != NULL) {
        log_info("XDP program will be attached to %s interface", iface2);
        ifindex_iface2 = if_nametoindex(iface2);
        if (!ifindex_iface2) {
            log_fatal("Error while retrieving the ifindex of %s", iface2);
            exit(1);
        } else {
            log_info("Got ifindex for iface: %s, which is %d", iface2, ifindex_iface2);
        }
    } else {
        log_error("Error, you must specify the interface where to attach the XDP program");
        exit(1);
    }

    /* Open BPF application */
    skel = vlan_handler_bpf__open();
    if (!skel) {
        log_fatal("Error while opening BPF skeleton");
        exit(1);
    }

    /* Add iface configuration to vlan_handler.cfg */
    skel->rodata->vlan_handler_cfg.ifindex_if1 = ifindex_iface1;
    skel->rodata->vlan_handler_cfg.ifindex_if2 = ifindex_iface2;
    skel->rodata->vlan_handler_cfg.vlan_id = 100;

    /* Set program type to XDP */
    bpf_program__set_type(skel->progs.xdp_vlan_handler, BPF_PROG_TYPE_XDP);

    /* Load and verify BPF programs */
    if (vlan_handler_bpf__load(skel)) {
        log_fatal("Error while loading BPF skeleton");
        exit(1);
    }

    struct sigaction action;
    memset(&action, 0, sizeof(action));
    action.sa_handler = &sigint_handler;

    if (sigaction(SIGINT, &action, NULL) == -1) {
        log_error("sigation failed");
        goto cleanup;
    }

    if (sigaction(SIGTERM, &action, NULL) == -1) {
        log_error("sigation failed");
        goto cleanup;
    }

    xdp_flags = 0;
    xdp_flags |= XDP_FLAGS_DRV_MODE;

    /* Attach the XDP program to the interface */
    err = bpf_xdp_attach(ifindex_iface1, bpf_program__fd(skel->progs.xdp_vlan_handler), xdp_flags, NULL);

    if (err) {
        log_fatal("Error while attaching 1st XDP program to the interface");
        goto cleanup;
    }

    /* Attach the XDP program to the interface */
    err = bpf_xdp_attach(ifindex_iface2, bpf_program__fd(skel->progs.xdp_vlan_handler), xdp_flags, NULL);

    if (err) {
        log_fatal("Error while attaching 2nd XDP program to the interface");
        goto cleanup;
    }

    log_info("Successfully attached!");

    sleep(10000);

cleanup:
    cleanup_ifaces();
    vlan_handler_bpf__destroy(skel);
    log_info("Program stopped correctly");
    return -err;
}