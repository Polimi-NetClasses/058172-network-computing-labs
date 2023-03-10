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
from scapy.all import Ether, IP, UDP, TCP

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
    parser.add_argument("-d", "--destination", required=True, type=str, help="The IP address of the destination")
    parser.add_argument("-m", "--message", type=str, required=True, help="Message to send")
    
    args = parser.parse_args()

    ip_addr = args.destination
    message = args.message

    addr = socket.gethostbyname(ip_addr)
    iface = get_if()

    tos = 0

    ether_dst = get_dst_mac(addr)

    if not ether_dst:
        print("Mac address for %s was not found in the ARP table" % addr)
        exit(1)

    print("Sending on interface %s to %s" % (iface, str(addr)))
    pkt =  Ether(src=get_if_hwaddr(iface), dst=ether_dst)
    pkt = pkt /IP(dst=addr,tos=tos) / message
    sendp(pkt, iface=iface, verbose=False)


if __name__ == '__main__':
    main()