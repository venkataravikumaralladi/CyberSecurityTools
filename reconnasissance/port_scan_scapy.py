# -*- coding: utf-8 -*-
"""
Created on Fri Dec 21 14:57:13 2021

@author: Venkata Ravi Kumar A

Notes:
    This is part of active reconassiance. Here we perform active port scanning by
    scanning the target which we received as part of passive reconassiance. (for 
    example IP address received during passive reconossiance e.g., shodan_search.py)
    
    In this file we define three different types of scans which are designed
    to collect certain types of information about a target system in a few 
    different ways. We use 'scapy' tool for scanning purpose. Scapy module allows
    us to build custom packets. This tool allow us to scan particular ports instead
    of flooding of packets so we want to avoid detection.
    
    1. Syn scan:
        This is an example of SYN scan and this comes from the fact that we are using
        TCP connection handshake(SYN, SYN-ACK, ACK). Here we are trying to check
        if port is open. So if we send SYN and we got SYN-ACK response means that
        particular port is open.
        
     After SYN-scan we know what ports are open. Next we want to learn what is
     program running at those ports. This done through banner grabbing.
     A banner grab is where you connect to a particular service and see what it 
     sends back which may give us some hints about what service actually is
     and can help inform some vulnerability analysis.
        
    2. Banner grabbing:
        There are two differnt types of banner grabbing.
             i. Classic grabbing (bannerGrab): Just send a messgae to packet and
                and see the response. We can build the packet in scapy manually
                but here we use socket API's. 
            ii. HTTPHeader banner grab (HTTPHeaderGrab): This will allow us
                to get information about what server it is running.

       
    Summary:
        We'll use the SYN scan to learn about ports. We'll use banner grabbing and
        HTTP header grabbing to start identifying information about the targets services,
        so we can start learning about potential vulnerabilities on them.
            
    
"""

from scapy.all import sr, IP, TCP, UDP, socket, DNS, DNSQR
import requests


class PortScanWithScapy:
    '''
    Scan the target to check commonly used ports open or not. This script helps
    us to avoid detection with tools as we try to avoid flodding packets.
    '''
    def __init__(self):
        '''
        Constructor for PortScanWithScapy class

        Returns
        -------
        None.

        '''
        self.ports_to_scan = [20,21,22,23,25,53,69,80,110,143,161,162,389,443,445,636,8080,8443]
        return

    def syn_scan(self, host:str)->list:
        '''
        API to perform TCP SYN scan to check port is open or not

        Parameters
        ----------
        host : str
            IP address of target to check for open ports.

        Returns
        -------
        list
            return list of open ports.

        '''
        # sr stands for send/receive. flag 'S' stands for SYN. send the packet
        # and listen for response. scapy module internally matches response for 
        # corresponding send packet.
        ans,unans = sr(IP(dst=host)/TCP(dport=self.ports_to_scan,flags="S"),timeout=2,verbose=0)
        # for answered response we have pair (request from source, response from destination)
        # we are checking for destination port in request is matching to response source port which we are
        # interested. And check for TCP flag SYN-ACK as response
        p = [s[TCP].dport for (s,r) in ans if s[TCP].dport == r[TCP].sport and r[TCP].flags=='SA']
        return p


    def banner_grab(self, ip:str, port:int)->str:
        '''
        General banner grab on specified port to get banner information like
        application name and version which can help in getting vulnerable information.

        Parameters
        ----------
        ip : str
            IP address of target.
        port : int
            port number of application to get banner information

        Returns
        -------
        str
            service name and verion if response received.

        '''
        if port in [53,6980,443]:
            return ""
    
        try:
            s = socket.socket()
            s.settimeout(2)
            s.connect((ip, port))
            # read 1024 bytes and use it for later analysis.
            banner = s.recv(1024)
            return banner.decode('utf-8')
        except Exception as e:
            print('port_scan_scapy::bannergrab Exception: {} '.format(e))
            return

    # Another banner grab is for HTTP header grab. This is only for HTTP ports like 80 and 443
    
    def http_header_grab(self, ip:str, port:str)->str:
        '''
        Grabs http header responses

        Parameters
        ----------
        ip : str
            IP address of target.
        port : str
            port number or web address to get response.

        Returns
        -------
        str
            HTTP response.

        '''
        try:
            if port == 443:
                # below verify = False for certificate verification .
                # and we don't really care about the authenticity of the certificate here because 
                # we're not really trusting the website. We just want to learn what's going on there
                response = requests.head('https://%s:%s'%(ip, port), verify=False)
            else:
                response = requests.head('http://%s:%s'%(ip, port), verify=False)
            return response
      
        except Exception as e:
            print('port_scan_scapy::http_header_grab exception {}'.format(e))
            return

    def dns_scan(self, host:str)->bool:
        '''
        performs DNS scan using scapy.

        Parameters
        ----------
        host : str
            IP address of target.

        Returns
        -------
        bool
            true if DNS server is running else false.

        '''
        ans,unans = sr(IP(dst=host)/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="google.com")),timeout=2,verbose=0)
        if ans:
            return True
        return False
    
if __name__ == '__main__':
    # unit test code.
    host = '216.239.32.10'
    port_scan = PortScanWithScapy()
    print('*********************************************')
    open_ports = port_scan.syn_scan(host)
    print('Open ports for {} are {} '.format(host, open_ports))
    
    # Get banner report for open port received.
    if len(open_ports) != 0:
        # banner scan one of open port
        print('*********************************************')
        banner = port_scan.banner_grab(host, open_ports[0])
        print('Banner for port {} is {} '.format(open_ports[0], banner))
        
    # Banner scan for HTTP header to get server information
    response = port_scan.http_header_grab("www.google.com", 443)
    print('Response for www.google.com received as ', response)
    print('*********************************************')
    print('Response header for www.google.com recevievd as ', response.headers)
    
    print('*********************************************')
    is_dns = port_scan.dns_scan(host)
    print('{} DNS sever is running'.format(is_dns))



