// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <arpa/inet.h>
#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <linux/if_link.h>
#include <netinet/in.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <argparse.h>
#include <net/if.h>

#ifndef __USE_POSIX
#define __USE_POSIX
#endif
#include <signal.h>

#include "hhd_v2.h"
#include "log.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define DEFAULT_THRESHOLD 50

static const char *const usages[] = {
    "hhd_v2 [options] [[--] args]",
    "hhd_v2 [options]",
    NULL,
};

struct ipv4_lookup_val {
    __u8 dstMac[6];
    __u8 outPort;
};

struct src_mac_val {
    __u8 srcMac[6];
};

int load_maps_config(struct hhd_v2_bpf *skel, const char *config_file, mac_t *macs) {
    struct ips *ips;
    cyaml_err_t err;
    int ret = EXIT_SUCCESS;

    /* Load input file. */
    err = cyaml_load_file(config_file, &config, &ips_schema, (void **)&ips, NULL);
    if (err != CYAML_OK) {
        fprintf(stderr, "ERROR: %s\n", cyaml_strerror(err));
        return EXIT_FAILURE;
    }

    log_info("Loaded %d IPs", ips->ips_count);

    // Get fd of ipv4_lookup_map
    int ipv4_lookup_map_fd = bpf_map__fd(skel->maps.ipv4_lookup_map);

    // Check if the file descriptor is valid
    if (ipv4_lookup_map_fd < 0) {
        log_error("Failed to get file descriptor of BPF map: %s", strerror(errno));
        ret = EXIT_FAILURE;
        goto cleanup_yaml;
    }

    struct ipv4_lookup_val val = {0};

    /* Load the IPs in the BPF map */
    for (int i = 0; i < ips->ips_count; i++) {
        log_info("Loading IP %s", ips->ips[i].ip);
        log_info("Port: %d", ips->ips[i].port);
        log_info("MAC dst: %s", ips->ips[i].mac);

        // Convert the IP to an integer
        struct in_addr addr;
        int ret = inet_pton(AF_INET, ips->ips[i].ip, &addr);
        if (ret != 1) {
            log_error("Failed to convert IP %s to integer", ips->ips[i].ip);
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }

        // Convert the MAC string to an array of bytes
        ret =
            sscanf(ips->ips[i].mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &val.dstMac[0], &val.dstMac[1],
                   &val.dstMac[2], &val.dstMac[3], &val.dstMac[4], &val.dstMac[5]);

        if (ret != 6) {
            log_error("Failed to convert MAC %s to array of bytes", ips->ips[i].mac);
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }

        if (ips->ips[i].port < 1) {
            log_error("You cannot specify a port < 1");
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }

        val.outPort = ips->ips[i].port;

        ret = bpf_map_update_elem(ipv4_lookup_map_fd, &addr.s_addr, &val, BPF_ANY);
        if (ret != 0) {
            log_error("Failed to update BPF map: %s", strerror(errno));
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }
    }

    /* Let's now load the Source MACs into the map */
    // Get fd of src_mac_map
    int src_mac_map_fd = bpf_map__fd(skel->maps.src_mac_map);

    // Check if the file descriptor is valid
    if (src_mac_map_fd < 0) {
        log_error("Failed to get file descriptor of BPF map: %s", strerror(errno));
        ret = EXIT_FAILURE;
        goto cleanup_yaml;
    }

    struct src_mac_val mac_val = {0};

    /* Load the MACs in the BPF map */
    for (int i = 0; i < ips->ips_count; i++) {
        __u16 src_mac_key = ips->ips[i].port;
        log_info("MAC src: %02x:%02x:%02x:%02x:%02x:%02x", macs[src_mac_key][0],
                 macs[src_mac_key][1], macs[src_mac_key][2], macs[src_mac_key][3],
                 macs[src_mac_key][4], macs[src_mac_key][5]);

        for (int j = 0; j < 6; j++) {
            mac_val.srcMac[j] = macs[src_mac_key][j];
        }

        ret = bpf_map_update_elem(src_mac_map_fd, &src_mac_key, &mac_val, BPF_ANY);
        if (ret != 0) {
            log_error("Failed to update BPF map: %s", strerror(errno));
            ret = EXIT_FAILURE;
            goto cleanup_yaml;
        }
    }

cleanup_yaml:
    /* Free the data */
    cyaml_free(&config, &ips_schema, ips, 0);

    return ret;
}

int main(int argc, const char **argv) {
    struct hhd_v2_bpf *skel = NULL;
    int err;
    int threshold = DEFAULT_THRESHOLD;
    const char *config_file = NULL;
    const char *iface1 = NULL;
    const char *iface2 = NULL;
    const char *iface3 = NULL;
    const char *iface4 = NULL;

    struct argparse_option options[] = {
        OPT_HELP(),
        OPT_GROUP("Basic options"),
        OPT_STRING('c', "config", &config_file, "Path to the YAML configuration file", NULL, 0, 0),
        OPT_INTEGER('t', "threshold", &threshold, "Value of the threshold to use", NULL, 0, 0),
        OPT_STRING('1', "iface1", &iface1, "1st interface where to attach the BPF program", NULL, 0, 0),
        OPT_STRING('2', "iface2", &iface2, "2nd interface where to attach the BPF program", NULL, 0, 0),
        OPT_STRING('3', "iface3", &iface2, "3rd interface where to attach the BPF program", NULL, 0, 0),
        OPT_STRING('4', "iface4", &iface2, "4th interface where to attach the BPF program", NULL, 0, 0),
        OPT_END(),
    };

    struct argparse argparse;
    argparse_init(&argparse, options, usages, 0);
    argparse_describe(&argparse,
                      "\n[Exercise 6] This software attaches an XDP program to "
                      "the interface specified in the input parameter",
                      "\nThe '-1/2/3/4' argument is used to specify the "
                      "interface where to attach the program");
    argc = argparse_parse(&argparse, argc, argv);

    if (config_file == NULL) {
        log_warn("Use default configuration file: %s", "config.yaml");
        config_file = "config.yaml";
    }

    /* Check if file exists */
    if (access(config_file, F_OK) == -1) {
        log_fatal("Configuration file %s does not exist", config_file);
        exit(1);
    }

    get_iface_ifindex(iface1, iface2, iface3, iface4);

    /* Open BPF application */
    skel = hhd_v2_bpf__open();
    if (!skel) {
        log_fatal("Error while opening BPF skeleton");
        exit(1);
    }

    __u32 ifindexes[] = {ifindex_iface1, ifindex_iface2, ifindex_iface3, ifindex_iface4};

    /* Let's now allocate with malloc an array of mac addresses */
    mac_t *macs = malloc(ARRAY_SIZE(ifindexes) * sizeof(mac_t));
    if (!macs) {
        log_fatal("Error while allocating memory");
        goto cleanup;
    }

    err = get_mac_for_every_iface(macs, ifindexes, ARRAY_SIZE(ifindexes));
    if (err) {
        log_fatal("Error while getting MAC addresses");
        goto cleanup;
    }

    log_info("Configuring BPF program with threshold %d", threshold);
    /* Add iface configuration to hhd_v2.cfg */
    skel->rodata->hhd_v2_cfg.threshold = threshold;

    /* Set program type to XDP */
    bpf_program__set_type(skel->progs.xdp_hhd_v2, BPF_PROG_TYPE_XDP);

    /* Load and verify BPF programs */
    if (hhd_v2_bpf__load(skel)) {
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

    /* Let's configure the devmap before attaching the program */
    err = configure_devmap(skel, ifindexes, ARRAY_SIZE(ifindexes));
    if (err) {
        log_fatal("Error while configuring devmap");
        goto cleanup;
    }

    /* Before attaching the program, we can also load the map configuration */
    err = load_maps_config(skel, config_file, macs);
    if (err) {
        log_fatal("Error while loading map configuration");
        goto cleanup;
    }

    free(macs);

    xdp_flags = 0;
    xdp_flags |= XDP_FLAGS_DRV_MODE;

    err = attach_bpf_progs(xdp_flags, skel);
    if (err) {
        log_fatal("Error while attaching BPF programs");
        goto cleanup;
    }

    log_info("Successfully attached!");

    sleep(10000);

cleanup:
    cleanup_ifaces();
    /* Check if macs has been already freed */
    if (macs) {
        free(macs);
    }
    hhd_v2_bpf__destroy(skel);
    log_info("Program stopped correctly");
    return -err;
}