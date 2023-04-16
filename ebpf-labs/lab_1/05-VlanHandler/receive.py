#!/usr/bin/env python3
#
# Copyright (c) Networked Systems Group (NSG) ETH Zürich.
import sys
import os

from scapy.all import sniff, get_if_list, Ether, get_if_hwaddr, IP, Raw, Dot1Q
import argparse

def isNotOutgoing(my_mac):
    my_mac = my_mac
    def _isNotOutgoing(pkt):
        return pkt[Ether].src != my_mac

    return _isNotOutgoing

def handle_pkt(pkt):

    print("Packet Received:")
    ether = pkt.getlayer(Ether)
    ip = pkt.getlayer(IP)
    msg = ip.payload

    print("###[ Ethernet ]###")
    print("  src: {}".format(ether.src))
    print("  dst: {}".format(ether.dst))
    # check if packet has vlan header
    if pkt.haslayer(Dot1Q):
        vlan = pkt.getlayer(Dot1Q)
        print("###[ VLAN ]###")
        print("  pri: {}".format(vlan.prio))
        print("  dei: {}".format(vlan.id))
        print("  vlan id: {}".format(vlan.vlan))
    
    print("###[ IP ]###")
    print("  src: {}".format(ip.src))
    print("  dst: {}".format(ip.dst))

def main():
    parser = argparse.ArgumentParser(description='Script to send packets to a specific destination')
    parser.add_argument("-i", "--iface", required=True, type=str, help="The name of the interface")

    args = parser.parse_args()

    iface = args.iface
    print("sniffing on %s" % iface)
    sys.stdout.flush()

    my_filter = isNotOutgoing(get_if_hwaddr(iface))

    sniff(filter="ip", iface = iface,
          prn = lambda x: handle_pkt(x), lfilter=my_filter)

if __name__ == '__main__':
    main()