#!/usr/bin/env python3
#
# Copyright (c) Networked Systems Group (NSG) ETH Zürich.
import sys
import socket
import random
from subprocess import Popen, PIPE
import re
import argparse

from scapy.all import sendp, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, UDP, TCP, Dot1Q

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def get_dst_mac(ip):

    try:
        pid = Popen(["arp", "-n", ip], stdout=PIPE)
        s = str(pid.communicate()[0])
        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
        return mac
    except:
        return None

def main():
    parser = argparse.ArgumentParser(description='Script to send packets to a specific destination')
    parser.add_argument("-i", "--iface", required=True, type=str, help="The name of the interface")
    parser.add_argument("-d", "--destination", required=True, type=str, help="The IP address of the destination")
    parser.add_argument("-v", "--vlan", type=int, help="VLAN ID to use")
    
    args = parser.parse_args()

    ip_addr = args.destination
    vlan_id = args.vlan

    #check if vlan id is valid
    if vlan_id is not None and (vlan_id < 0 or vlan_id > 4095):
        print("VLAN ID must be between 0 and 4095")
        exit(1)

    addr = socket.gethostbyname(ip_addr)
    iface = args.iface

    tos = 0

    ether_dst = get_dst_mac(addr)

    if not ether_dst:
        print("Mac address for %s was not found in the ARP table" % addr)
        exit(1)

    print("Sending on interface %s to %s" % (iface, str(addr)))
    pkt =  Ether(src=get_if_hwaddr(iface), dst=ether_dst)

    if vlan_id is not None:
        # Add VLAN header to pkt
        pkt = pkt / Dot1Q(vlan=vlan_id)
    
    pkt = pkt /IP(dst=addr,tos=tos)
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()