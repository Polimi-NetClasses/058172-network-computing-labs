#!/usr/bin/env python3
#
# Copyright (c) Networked Systems Group (NSG) ETH Zürich.
import sys
import os

from scapy.all import sniff, get_if_list, Ether, get_if_hwaddr, IP, Raw, Dot1Q

def get_if():
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def isNotOutgoing(my_mac):
    my_mac = my_mac
    def _isNotOutgoing(pkt):
        return pkt[Ether].src != my_mac

    return _isNotOutgoing

totals = {}

def handle_pkt(pkt):
    ether = pkt.getlayer(Ether)
    ip = pkt.getlayer(IP)
    msg = ip.payload

    eth_src = ether.src
    eth_dst = ether.dst
    src_ip = ip.src
    dst_ip = ip.dst
    msg = str(msg)

    if src_ip not in totals:
        totals[src_ip] = 0
    totals[src_ip] += 1

    id_tup = (eth_src, eth_dst, src_ip, dst_ip, msg)
    print("Received from %s total: %s" % (id_tup, totals[src_ip]))

def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()

    my_filter = isNotOutgoing(get_if_hwaddr(get_if()))

    sniff(filter="ip", iface = iface,
          prn = lambda x: handle_pkt(x), lfilter=my_filter)

if __name__ == '__main__':
    main()