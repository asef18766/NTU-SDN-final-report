#!/usr/bin/env python3
import socket
import sys

from scapy.all import (
    IP,
    Ether,
    get_if_hwaddr,
    get_if_list,
    sendp,
    rdpcap,
    TCP,
    Raw
)
from scapy.fields import *


def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    if len(sys.argv)<2:
        print('pass 2 arguments: <destination>')
        exit(1)
    
    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    print("sending on interface %s to %s" % (iface, str(addr)))
    
    # read cert pcap
    # pk = rdpcap('1.pcap')
    # pk7 = pk[7]

    eth = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    # load = pk7[Raw].load[0:12] + pk7[Raw].load[1824:1824+900]

    pkt = eth / IP(dst=addr,len=2000) / TCP(dport=1234,sport=4321) /sys.argv[2]
    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)



if __name__ == '__main__':
    main()
