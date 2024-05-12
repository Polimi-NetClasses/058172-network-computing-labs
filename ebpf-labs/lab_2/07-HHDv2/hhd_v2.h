#ifndef HHD_V2_H_
#define HHD_V2_H_

#include <assert.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <unistd.h>

#include <cyaml/cyaml.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netlink/netlink.h>
#include <netlink/route/addr.h>
#include <netlink/route/link.h>
#include <netlink/route/qdisc.h>
#include <netlink/socket.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "log.h"

// Include skeleton file
#include "hhd_v2.skel.h"

typedef unsigned char mac_t[6];

static int ifindex_iface1 = 0;
static int ifindex_iface2 = 0;
static int ifindex_iface3 = 0;
static int ifindex_iface4 = 0;
static __u32 xdp_flags = 0;

struct ip {
    const char *ip;
    uint8_t port;
    const char *mac;
    const char *gw;
};

struct ips {
    struct ip *ips;
    uint64_t ips_count;
};

static const cyaml_schema_field_t ip_field_schema[] = {
    CYAML_FIELD_STRING_PTR("ip", CYAML_FLAG_POINTER, struct ip, ip, 0, CYAML_UNLIMITED),
    CYAML_FIELD_STRING_PTR("mac", CYAML_FLAG_POINTER, struct ip, mac, 0, 18),
    CYAML_FIELD_STRING_PTR("gw", CYAML_FLAG_POINTER, struct ip, gw, 0, CYAML_UNLIMITED),
    CYAML_FIELD_UINT("port", CYAML_FLAG_DEFAULT, struct ip, port), CYAML_FIELD_END};

static const cyaml_schema_value_t ip_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_DEFAULT, struct ip, ip_field_schema),
};

static const cyaml_schema_field_t ips_field_schema[] = {
    CYAML_FIELD_SEQUENCE("ips", CYAML_FLAG_POINTER, struct ips, ips, &ip_schema, 0,
                         CYAML_UNLIMITED),
    CYAML_FIELD_END};

static const cyaml_schema_value_t ips_schema = {
    CYAML_VALUE_MAPPING(CYAML_FLAG_POINTER, struct ips, ips_field_schema),
};

static const cyaml_config_t config = {
    .log_fn = cyaml_log,            /* Use the default logging function. */
    .mem_fn = cyaml_mem,            /* Use the default memory allocator. */
    .log_level = CYAML_LOG_WARNING, /* Logging errors and warnings only. */
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

    if (ifindex_iface3 != 0) {
        if (!bpf_xdp_query_id(ifindex_iface3, xdp_flags, &curr_prog_id)) {
            if (curr_prog_id) {
                bpf_xdp_detach(ifindex_iface3, xdp_flags, NULL);
                log_trace("Detached XDP program from interface %d", ifindex_iface3);
            }
        }
    }

    if (ifindex_iface4 != 0) {
        if (!bpf_xdp_query_id(ifindex_iface4, xdp_flags, &curr_prog_id)) {
            if (curr_prog_id) {
                bpf_xdp_detach(ifindex_iface4, xdp_flags, NULL);
                log_trace("Detached XDP program from interface %d", ifindex_iface4);
            }
        }
    }
}

int create_devmap_entry(int devmap_fd, __u32 key, __u32 val) {
    int err = 0;

    /* Create devmap entry for the first ifindex */
    err = bpf_map_update_elem(devmap_fd, &key, &val, BPF_ANY);

    if (err) {
        log_fatal("Error while creating devmap entry");
        return err;
    }

    return 0;
}

int configure_devmap(struct hhd_v2_bpf *skel, __u32 *ifindexes, int ifindexes_count) {
    int err = 0;

    /* First, let's get the fd of the devmap */
    int devmap_fd = bpf_map__fd(skel->maps.devmap);

    /* Check if fd is valid */
    if (devmap_fd < 0) {
        log_fatal("Invalid devmap fd");
        return -1;
    }

    for (int i = 0; i < ifindexes_count; i++) {
        __u32 key = i + 1;
        __u32 value = ifindexes[i];

        log_debug("Creating devmap entry for port %d and ifindex %d", key, value);

        /* Create devmap entry for the first ifindex */
        err = create_devmap_entry(devmap_fd, key, value);

        if (err) {
            log_fatal("Error while creating devmap entry");
            return err;
        }
    }

    return 0;
}

int attach_bpf_progs(unsigned int xdp_flags, struct hhd_v2_bpf *skel) {
    int err = 0;
    /* Attach the XDP program to the interface */
    err = bpf_xdp_attach(ifindex_iface1, bpf_program__fd(skel->progs.xdp_hhd_v2), xdp_flags, NULL);

    if (err) {
        log_fatal("Error while attaching 1st XDP program to the interface");
        return err;
    }

    /* Attach the XDP program to the interface */
    err = bpf_xdp_attach(ifindex_iface2, bpf_program__fd(skel->progs.xdp_hhd_v2), xdp_flags, NULL);

    if (err) {
        log_fatal("Error while attaching 2nd XDP program to the interface");
        return err;
    }

    /* Attach the XDP program to the interface */
    err = bpf_xdp_attach(ifindex_iface3, bpf_program__fd(skel->progs.xdp_hhd_v2), xdp_flags, NULL);

    if (err) {
        log_fatal("Error while attaching 3rd XDP program to the interface");
        return err;
    }

    /* Attach the XDP program to the interface */
    err = bpf_xdp_attach(ifindex_iface4, bpf_program__fd(skel->progs.xdp_hhd_v2), xdp_flags, NULL);

    if (err) {
        log_fatal("Error while attaching 4th XDP program to the interface");
        return err;
    }

    return 0;
}

static void get_iface_ifindex(const char *iface1, const char *iface2, const char *iface3,
                              const char *iface4) {
    if (iface1 == NULL) {
        log_warn("No interface specified, using default one (veth1)");
        iface1 = "veth1";
    }

    log_info("XDP program will be attached to %s interface", iface1);
    ifindex_iface1 = if_nametoindex(iface1);
    if (!ifindex_iface1) {
        log_fatal("Error while retrieving the ifindex of %s", iface1);
        exit(1);
    } else {
        log_info("Got ifindex for iface: %s, which is %d", iface1, ifindex_iface1);
    }

    if (iface2 == NULL) {
        log_warn("No interface specified, using default one (veth2)");
        iface2 = "veth2";
    }

    log_info("XDP program will be attached to %s interface", iface2);
    ifindex_iface2 = if_nametoindex(iface2);
    if (!ifindex_iface2) {
        log_fatal("Error while retrieving the ifindex of %s", iface2);
        exit(1);
    } else {
        log_info("Got ifindex for iface: %s, which is %d", iface2, ifindex_iface2);
    }

    if (iface3 == NULL) {
        log_warn("No interface specified, using default one (veth3)");
        iface3 = "veth3";
    }

    log_info("XDP program will be attached to %s interface", iface3);
    ifindex_iface3 = if_nametoindex(iface3);
    if (!ifindex_iface3) {
        log_fatal("Error while retrieving the ifindex of %s", iface3);
        exit(1);
    } else {
        log_info("Got ifindex for iface: %s, which is %d", iface3, ifindex_iface3);
    }

    if (iface4 == NULL) {
        log_warn("No interface specified, using default one (veth3)");
        iface4 = "veth4";
    }

    log_info("XDP program will be attached to %s interface", iface4);
    ifindex_iface4 = if_nametoindex(iface4);
    if (!ifindex_iface4) {
        log_fatal("Error while retrieving the ifindex of %s", iface4);
        exit(1);
    } else {
        log_info("Got ifindex for iface: %s, which is %d", iface4, ifindex_iface4);
    }
}

int get_mac_from_ifindex(int ifindex, unsigned char mac_str[6]) {
    struct ifreq ifr;
    int fd, rv;

    char ifname[IF_NAMESIZE];
    if (if_indextoname(ifindex, ifname) == NULL) {
        log_error("if_indextoname error: %s\n", strerror(errno));
        return -1;
    }

    strcpy(ifr.ifr_name, ifname);
    fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (fd < 0) {
        log_error("get_iface_mac error opening socket: %s\n", strerror(errno));
        return -1;
    }

    rv = ioctl(fd, SIOCGIFHWADDR, &ifr);
    if (rv >= 0) {
        log_debug("Got the MAC address for ifindex %d", ifindex);
        /* Print the MAC address */
        log_debug(
            "MAC address for %s is %02x:%02x:%02x:%02x:%02x:%02x", ifname,
            (unsigned char)ifr.ifr_hwaddr.sa_data[0], (unsigned char)ifr.ifr_hwaddr.sa_data[1],
            (unsigned char)ifr.ifr_hwaddr.sa_data[2], (unsigned char)ifr.ifr_hwaddr.sa_data[3],
            (unsigned char)ifr.ifr_hwaddr.sa_data[4], (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

        memcpy(mac_str, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);
    } else {
        close(fd);
        if (errno == NLE_NOADDR || errno == NLE_NODEV) {
            // Device has been deleted
            return -2;
        }

        log_error("get_iface_mac error determining the MAC address: %s\n", strerror(errno));
    }

    close(fd);
    return 0;
}

int get_mac_for_every_iface(mac_t *macs, __u32 *ifindexes, int ifindexes_count) {
    for (int i = 0; i < ifindexes_count; i++) {
        if (get_mac_from_ifindex(ifindexes[i], macs[i]) < 0) {
            log_error("Error while getting MAC address for ifindex %d", ifindexes[i]);
            return -1;
        }
    }
    return 0;
}

void sigint_handler(int sig_no) {
    log_debug("Closing program...");
    cleanup_ifaces();
    exit(0);
}

#endif // HHD_V2_H_
