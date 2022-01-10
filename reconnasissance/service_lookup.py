# -*- coding: utf-8 -*-
"""
Created on Wed Dec 22 11:02:26 2021

@author: INVERAV
"""
'''
 We have collected lot of information from Shodan (shodan_search.py),
 DNS identifying subdomains (dns_search.py), port scan and banner grabbing for
 particular information (port_scan_scapy.py).
 With above tools we have little bits and pieces of information, but not in 
 usable form. What we need is product name and version number which is useful
 in identifying CVE's.'

 To make it in usable form we use this script (service_lookup.py) a program 
 This program will interact with lot of other programs mentioned above.
 and then parse it to make it useful.

'''

from shodan_search import ShodanSearch
from port_scan_scapy import PortScanWithScapy
import re, requests, socket
from shodan import *

defaults = {
  'smtp':[25],
  'dns':[53],
  'ns':[53],
  'web':[80, 443],
  'www':[80, 443],
  'api':[80, 443],
  'ftp':[20, 21]
}

class ServiceLookup:
    '''
    '''
    def __init__(self):
        self.port_scan_helper = PortScanWithScapy()
        with open('shodan_api_key.txt', 'r') as f:
            key = f.read()
    
        self.shodan_helper    = ShodanSearch(key)
        return
    
    def service_id(self, ip:str, subs:list)->list:
        '''
        Here we use shodan, DNS, port scan, banner scan information to get all
        information for particular IP address. We look services in three different
        ways, i. using sub-domains (we can guess what this computer is supposed to do),
             ii. using shodan iii. using scan reports.
             
        In the end, what we're hoping to end up with is something to parse. So either
        the server header from HTTP header or whatever the service spits out in response
        to a banner grabbing request.

        Parameters
        ----------
        ip : str
            IP address of target.
        subs : list
            sub domain list. (can be obtained from dns_search)

        Returns
        -------
        list
            service ID's.

        '''
        
        records = []
        # check default ports
        for sub in subs:
            # strip of numbers from subdomain names for eg ns1 as ns
            s = sub.strip('0123456789')
            if s in defaults:
                # once we know ports we want to know what application is running on these ports
                # this can be achieved through banner information.
                records = [self.banner_record(ip, p) for p in defaults[s]]

        # check Shodan
        if len(records) == 0:
            shodan_records = self.shodan_helper.lookup(ip)
            # shodan results consists of port number and other information with given particular IP address.
            # we may get product information as part of the result if not try to get that from parse banner.
            # This banner is same sort of information we got as part of port scanning (port_scan_scapy.py)
            # in above banner_record API will call port scan helper function and call parse_banner
            print('service_lookup::service_id lenght of shodan result ', len(shodan_records))
            for r in shodan_records:
                if not 'product' in r:
                    prod_ver_lst = self.parse_banner(r['banner'], r['port']) 
                    r = { 'port':r['port'], 'product':prod_ver_lst[0], 'version': prod_ver_lst[1] }
                    records.append(r)    
                else:
                    r = { 'port':r['port'], 'product':r['product'], 'version': r['version'] }
                    records.append(r)
            
        # Scan common ports using SYN scan using TCP hand shake mechnanism, based on that
        # response we will read from that open report and parse the response for banner information.
        if len(records) == 0:
            records = [self.banner_record(ip, p) for p in self.port_scan_helper.syn_scan(ip)]
         
        return records
    
    def banner_record(self, ip:str, p:int)->dict:
        '''
        function is to identify product and version number of application running
        on given IP and port number
        
        Parameters
        ----------
        ip : str
            target IP address.
        p : int
            port number.

        Returns
        -------
        dict
            dictionary with keys port number, product name and version..

        '''
        
        
        product = ''
        version = ''
        
        # check for web ports which uses HTTP headers
        if p in [80, 443, 8080, 8443]:
            response = self.port_scan_helper.http_header_grab(ip, p)
            '''
            sample response.headers output shown below:
                {'Content-Type': 'text/html; charset=ISO-8859-1',
                 'P3P': 'CP="This is not a P3P policy! See g.co/p3phelp for more info."',
                 'Date': 'Mon, 27 Dec 2021 05:07:22 GMT', 
                 'Server': 'gws', 
                 'X-XSS-Protection': '0', 'X-Frame-Options': 'SAMEORIGIN',
                 'Transfer-Encoding': 'chunked', 'Expires': 'Mon, 27 Dec 2021 05:07:22 GMT',
                 'Cache-Control': 'private',
                 }
             We can see above Server in response in this case we got gws (google web server), there
             are other webservers like Apache webserver etc.
             '''
            server = response.headers['Server']
            [prodct, version] = self.parse_banner(server, p)
        else:
            # banner_grab calls just opens socket call on that port and see if we get any response.
            # and use that response to parse the data using parse_banner
            banner = self.port_scan_helper.banner_grab(ip, p)
            if banner:
                [product, version] = self.parse_banner(banner, p)
        # it could be possible at end we may not get product and version information empty as server
        # has implemented securely.
        r = {
            'port':p,
            'product': product,
            'version': version
            }
        return r
    
    def parse_banner(self, banner:str, port:int):
        
        product = ''
        version = ''
        #print('Port {} parse banner input {}  '.format(port, banner))
        
        if port in [80, 443, 8080, 8443]: # HTTP service
            # There are two options 1. server header that we have got from HTTP header grab
            # 2. We have response to HTTP request in Shodan
            # HTTP response starts with for example HTTP/1.1 200 OK
            if banner.startswith('HTTP'): # option 1
                # http response banner consists of for example Server: Apache/2.1.43
                # serach for particular substring Server: ([^\r\n]*) in banner 
                match = re.search('Server: ([^\r\n]*)', banner)
                if match:
                    # groups allow us to find the match for group in regular expr i.e., ([^\r\n]*)
                    # below server consists of 'Apache/2.1.43'
                    server = match.groups()[0]
                else:
                    server = ''
            else:
                server = banner # response from Shodan, for example gws from Shodan ouput
            
            # we split according to the standard HTTP format.
            vals = server.split(' ')[0].split('/')
            product = vals[0]
            version = vals[1] if len(vals) > 1 else ''
        else:
            '''
            We have any other services other than HTTP. Here we don't have nice server
            header like HTTP service that tells us where to look. So
            for other services we make educated guess on where we
            might find the product and version information.
            
            Often we'll have something like the product name,
            a delineating character or a delimiter, and then a version number. 
            
            That product name, not super-helpful because we don't know 
            what it looks like. However, our version number is something
            that typically has a standard format and hopefully it's a bit weird.
            You'll see something like 1.0, or 1.0.1, etc. 
            
            What we can look for is something like something, delimiting
            character, and it's something that looks like a version number.
            That's what we're doing here with this re.search. 
            This would match 1.1. It would also match 1.11, it would also match 1.0.1, etc
            '''
            product_info = re.search('([A-Za-z0-9]+)[/ _](([0-9]+([.][0-9]+)+))', banner)
            if product_info:
                product = product_info.groups()[0]
                version = product_info.groups()[1]
            else:
                # we will land here if version number is not provided.
                # We can try to use the knowledge of the services IP address is offering, 
                # For example, if you have an FTP server, there's a good chance that the word
                # FTP is in the product name so that you know what to look for
                # we can look for something that contains one of those hint words like SMTP or FTP.
                # in below serach we will allow alpha numeric character before and after SMTP or FTP
                services = re.findall('([a-z0-9]*((smtp) | (ftp))[a-z0-9]*)', banner.lower())
                if services:
                    #print('parse_banner x ', x)
                    for svc in services:
                        if svc[0] != 'esmtp': # esmtp is not a service name
                            product = svc[0]
                            break
        #NOTE: above is not prefect. If you want perect then use nmap tool
        return [product, version]
    
    

    

if __name__ == '__main__':
    
    # unit test code to test subdomains from google.com dns search
    print()
    print('Scenario 1: service lookup using dns search for www subdomain output')
    google_server_host = '142.251.45.36'
    subdomains = ['www']
    svc_lkup = ServiceLookup()
    
    # second argument is list of subdomains we collected from DNS search (d  ns_search.py).
    records = svc_lkup.service_id(google_server_host, subdomains)
    for r in records:
        print(r)
    
    print()
    
    print('Scenario 2: service lookup using dns search output')
    google_smtp_host = '142.250.113.26'
    subdomains = ['smtp']
    svc_lkup = ServiceLookup()
    
    # second argument is list of subdomains we collected from DNS search (dns_search.py).
    records = svc_lkup.service_id(google_smtp_host, subdomains)
    for r in records:
        print(r)
    
    print()
    print('Scenario 3: service lookup using shodan search output')
    google_host = '35.226.233.237'
    # in this unit test case I am not passing any thing to pretend that I don't know much 
    # about target system.
    records = svc_lkup.service_id(google_host, [])
    for r in records:
        print(r)
        
    print()
    print('Summary: Above demonstartes from IP address we can get software and versions used in \
           application and we can use that information to get CVE\'s and explore our \
           potential attack vectors')