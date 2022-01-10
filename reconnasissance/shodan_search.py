# -*- coding: utf-8 -*-
"""
Created on Fri Dec 17 08:57:13 2021

@author: Venkata Ravi Kumar A

Notes:
    Reconnaissiance is the first activity as part of ethical hacking.
    Reconnaissiance attacker/ethical hacker gets information about the
    target though open technical resources like Shodan or DNS. 
    
    This script we use Shodan to get information about out target.
    
    In reconnaissance, we have two different goals we might be wanting to achieve.
    
        1. We might want to go broad in reconnaissance. In our initial mapping
           of the attack surface, we need to know every single system that's
           associated with a particular organization or that meets certain criteria,
           such as IP address, port numbers open on that system running a
           particular type of service.
           This is achieved by "queryShodan" API below.
           
        2. The second goal of reconnaissance is to go deep and gather information 
           about a particular host. Say for example, we've determined that a 
           particular IP address is of interest, and so we just want to ask 
           Shodan about what is at that particular IP address.
           This is achieved by ShodanLookup API below
           
    Reference:
        Coursera InfoSec Advance Python Reconnasiance
           
"""
# import required modules.

from shodan import Shodan




class ShodanSearch:
    '''
        ShodanSearch class provides API's to get high level information and
        low information about the system.
    '''
    
    def __init__(self, key:str):
        '''
        Initialize Shadon API with key

        Parameters
        ----------
        key : str
            Shadon API key.

        Returns
        -------
        None.

        '''
        self.api = Shodan(key)
        return
    
    def query(self, query:str)->dict:
        '''
        Provides high level attack surface like IP address and port number.
        Queries Shadon for passed string. This provided attack surface information
        for passed target query string. 

        Parameters
        ----------
        query : str
            target system name to be searched for attacke surface
            for examxple "org:Google LLC".

        Returns
        -------
        dict
            returns dictionary IP systems and ports open on that IP system
            related to target query string 
            returns empty dictionary and prints error if exception occured.

        '''
        
        hosts = {}
        try:
            results = self.api.search(query)
            for service in results["matches"]:
                ip = service["ip_str"]
                ports = service["port"]
                if ip in hosts:
                    hosts[ip]["ports"] += ports
                else:
                    hosts[ip] = {"ports":ports}
            return hosts
        except Exception as e:
            print("shodan_search.py::query Exception %s" % e)
            return {}
    
    def lookup(self, ip:str)->list:
        '''
        Provides detailed information for IP address provided. This information
        includes ports opened on that system, banner information like what server
        and version system is running for example Apache 2.10.2.
        CVE's and CPE's repositories are widely used in Vulnerability 
        Management Systems (VMSs) to check for known vulnerabilities
        in software products. 
        
        This product, version information we see here will help us in 
        looking for Common Vulnerability Exposures (CVEs) for potentially
        exploitable vulnerabilities. 
        Example: CVE-2006-4838 
        
        This also provided Common Platform Enumeration (CPE) .
        Example: cpe:/o:microsoft:windows_xp:::pro
        
        Parameters
        ----------
        ip : str
            IP address for which detailed information to be provided.

        Returns
        -------
        list
            return  list of details of IP address.
            return null if error occurs.
            Sample output shown below
                {'port': 8081, 
                 'banner': 'HTTP/1.1 200 OK\r\nServer: Apache/2.1.43\r\n
                            Date: Wed, 15 Dec 2021 08:57:39 GMT',
                 'product': 'Apache httpd',
                 'version': '2.1.43',
                 'cpe': ['cpe:/a:apache:http_server:2.1.43']

        '''
        try:
            results = self.api.host(ip)
            records = []
            for item in results["data"]:
                r = {
    				"port":item["port"],
    				"banner":item["data"]
    			}
                if "product" in item:
                    r["product"] = item["product"]
                if "version" in item:
                    r["version"] = item["version"]
                if "cpe" in item: 
                    r["cpe"] = item["cpe"]
                records += [r]
            return records
        except Exception as e:
            print("shodan_search.py::lookup Exception %s" % e)
            return []
                
    	
                          
if __name__ == '__main__':
    # unit test code.
    with open('shodan_api_key.txt', 'r') as f:
        key = f.read()
    shodan_reconnasiance = ShodanSearch(key)
    high_level_attack_surface_results = shodan_reconnasiance.query('org:Google LLC')
    low_level_attack_surface_results = shodan_reconnasiance.lookup('35.226.233.237')
    print('low level details: ', len(low_level_attack_surface_results))
 
'''
sample output:

    Reloaded modules: shodan_search, port_scan_scapy
Error Please upgrade your API plan to use filters or paging.
low level details:  [{'port': 53, 'banner': '\n'},
                     {'port': 18081, 'banner': 'HTTP/1.1 200 OK\r\nServer: Apache/2.1.43\r\nDate: Mon, 27 Dec
                                                2021 04:10:26 GMT\r\nContent-Type: text/html; charset=utf8\r\n
                                                Content-Length: 1688029\r\n\r\n'}, 
                     {'port': 4369, 'banner': '\\n'}, {'port': 8089, 'banner': '\n'}, 
                     {'port': 10443, 'banner': '\n'}, {'port': 3097, 'banner': '\n'},
                     {'port': 27017, 'banner': '\\n'}, {'port': 10250, 'banner': '\n'},
                     {'port': 7444, 'banner': '\n'}, {'port': 5555, 'banner': '\n'},
                     {'port': 8622, 'banner': '\n'}, {'port': 8030, 'banner': '\n'}, 
                     {'port': 3057, 'banner': '\n'}, {'port': 27015, 'banner': '\\n'},
                     {'port': 11300, 'banner': '\n'}, {'port': 4157, 'banner': '\n'}, 
                     {'port': 18245, 'banner': '\\n'}, {'port': 8100, 'banner': '\n'},
                     {'port': 1494, 'banner': '\n'},
                     {'port': 7777, 'banner': 'HTTP/1.1 200 OK\r\nServer: Apache/2.1.43\r\nDate: Sat,
                                              25 Dec 2021 19:01:44 GMT\r\nContent-Type: text/html;
                                              charset=utf8\r\nContent-Length: 1686211\r\n\r\n'}, 
                                              
                    {'port': 35000, 'banner': '\\n'},
                    {'port': 8009, 'banner': '\\n'}, 
                    {'port': 8805, 'banner': '\n'},
                    {'port': 554, 'banner': '\n'},
                    {'port': 8025, 'banner': '\n'},
                    {'port': 2568, 'banner': '\n'},
                    {'port': 1599, 'banner': '\n'},
                    {'port': 8040, 'banner': '\n'}, 
                    {'port': 2066, 'banner': '\n'},
                    {'port': 7433, 'banner': '\n'},
                    {'port': 5900, 'banner': '\n'},
                    {'port': 8554, 'banner': '\n'},
                    {'port': 9151, 'banner': '\n'}, 
                    {'port': 502, 'banner': '\n'}, 
                    {'port': 9418, 'banner': 'HTTP/1.1 200 OK\r\nServer: Apache/2.1.43\r\n
                                              Date: Fri, 24 Dec 2021 06:04:49 GMT\r\nContent-Type:
                                              text/html; charset=utf8\r\nContent-Length: 1675360\r\n\r\n'}, 
                    {'port': 3306, 'banner': '5.7.16', 'product': 'MySQL', 'version': '5.7.16', 
                                             'cpe': ['cpe:/a:mysql:mysql:5.7.16']}
                    ]
                     
'''
                     
                        
