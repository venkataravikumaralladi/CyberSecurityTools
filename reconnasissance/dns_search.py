# -*- coding: utf-8 -*-
"""
Created on Fri Dec 17 08:57:13 2021

@author: Venkata Ravi Kumar A

Notes:
    Reconnaissiance is the first activity as part of ethical hacking.
    Reconnaissiance attacker/ethical hacker gets information about the
    target though open technical resources like Shodan or DNS. 
    
    This script we use DNS to get information about out target. Use the DNS
    to get the target organization structure.
    
    Job of DNS is to translate domain name in to IP address.
    
    
    Using DNS we can get IP address of high level domain name. We can also use
    sub-domain which is part of high level domain. For example mail.example.com.
    Usually top level domains like google.com. However, we have, within 
    an organization, a domain like google.com that refers to most or all
    of the sites under that organization's umbrella.
         
    A lot of times, there are subdomains, things like mail.google.com or
    vpn.google.com, etc, that are a special service within an organization.
    And so the reason why we care about these subdomains in particular is 
    because they're useful for learning about a particular organization 
    and what it does with its infrastructure.
    For example, if you have something that's called mail.example.com,
    you are probably running mail server.
    This is done using "sub_domain_search" API.
    
    After we get IP address we can scan for port numbers using Shodan script.
    
    Reference:
        Coursera InfoSec Advance Python Reconnasiance
 """
 
import dns
import dns.resolver
import socket

class DNSSearch:
    '''
        DNSSearch uses DNS tool as part of reconnaissiance to get IP address using
        domain name.
    '''
    def __init__(self, sub_domain_dict : dict):
        #  member dictionary that's going to map IP addresses to the 
        # subdomains associated with.
        self.sub_domain_dict = sub_domain_dict
        self.hosts= {}
        return
    
    def dns_serach(self, domain:str, nums:bool)->dict:
        '''
            This is helper function which we will use for integrating 
            reconnaissiance knowledge from DNS to rest of our reconnaissance 
            infrastructure.

        Parameters
        ----------
        domain : str
            domain name to be searched for..
        nums : bool
            True: if subdomains to be searched with numbers appended to subdomain.

        Returns
        -------
        dict
            contains IP addresses mapped to corresponding subdomains.

        '''
        self.hosts= {}
        self._sub_domain_search(domain, self.sub_domain_dict, nums)
        return self.hosts
    
    def _sub_domain_search(self, domain:str,
                          sub_domain_dict:dict,
                          nums:bool)->list:
        '''
         Subdomains tell us a little bit about what system that they're running 
         on is actually doing.
         
         A lot of times, there are subdomains, things like mail.google.com or
         vpn.google.com, etc, that are a special service within an organization.
         For example, if you have something that's called mail.example.com,
         you are probably running mail server.

        Parameters
        ----------
        domain : str
            high level domain for example google.com
        sub_domain_dict : dict
            sub domains dictionary like www, mail, vpn etc.
        nums : bool
            True: append numbers to subdomains as it is possible like www1.google.com.
            False: do not append numbers to subdomains.

        Returns
        -------
        list
            DESCRIPTION.

        '''
        for sub_domain in sub_domain_dict:
            self._dns_request(sub_domain, domain)
            if nums:
                for i in range(0,10):
                    sub_domain_num = sub_domain+str(i)
                    self._dns_request(sub_domain_num, domain)
        return
    
    def _dns_request(self, sub_domain:str, domain:str):
        '''
        Performs DNS request to get IP address correponding to the given domain
        and sub-domain. It also checks if other sub-domains are running on IP address
        returned by DNS.

        Parameters
        ----------
        sub_domain : str
            sub domain name like www, mail, etc.
        domain : str
            domain like .google.com

        '''
        try:
            hostname = sub_domain+domain
            result = dns.resolver.resolve(hostname)
            
            if result:
                for answer in result:
                    ip = answer.to_text()
                    # We do following because it is not uncommon for organizations
                    # to use the same server for multiple things. For example, 
                    # small organization may have mail server, a Web server etc,
                    # on a single computer.For example www and mail subdomains
                    # on the same computer. And so it's possible that we 
                    # didn't guess every subdomain for that computer. So we
                    # do ReverseDNS for IP provided to get host names.
                    hostnames = self._reverse_dns(ip)
                    subs = [sub_domain]
                    # we've got a list of host names that we've extracted for this
                    # particular system (IP address). And of these, we know that
                    # most or at least the ones we are interested in are going to end
                    # in domain name we are interested in (for eg .google.com.)
                    # Certainly possible the other ones will be produced here, 
                    # but we're going to focus on domain we are intersted right now. 
                    # And that's just for simplicity. 
                    # We could look at every single hostname for a computer, 
                    # and we might find that other types of domains are 
                    # associated with that organization as well.
                    # But to narrow our focus and make sure that we're only
                    # looking at the section i.e., domain we care about,
                    # we're going to stick with our current hostname. 
                    # So if everything ends with domain for example .google.com, 
                    # all we really have to store for these computers is their
                    # subdomains,that is going to become relevant later during 
                    # for peneration testing for example if we know it is mail sub domain 
                    # we can know port number. 
                    # So we'll loop over our hostnames that we've extracted
                    # from getting our original search (i.e., IP address from hostname
                    # and then also this ReverseDNS lookup. 
                    # We'll test to make sure that they all end with .google.com. 
                    for hostname in hostnames:
                       if hostname.endswith(domain):
                          s = hostname.rstrip(domain)
                          subs.append(s)
                    if ip in self.hosts:
                        s = self.hosts[ip]
                        self.hosts[ip] = list(dict.fromkeys(s+subs))
                    else:
                        self.hosts[ip] = list(dict.fromkeys(subs))
        except (dns.resolver.NXDOMAIN, dns.exception.Timeout):
            return
        except Exception as e:
            print("DNSRequest Error %s" % e)
            return
        return 
    
    
    def _reverse_dns(self, ip:str)->list:
        '''
        This function returns all host names linked to passed IP address.
        gethostbyaddr() returns a tuple containing
        Host Name, Alias list for the IP address if any, and
        IP address of the host.
        example of output: ('maa03s43-in-f4.1e100.net', [], ['142.250.195.228'])

        Parameters
        ----------
        ip : str
            IP address.

        Returns
        -------
        list
            list of host names for provided IP address.

        '''
        try:
            result = socket.gethostbyaddr(ip)
            return [result[0]]+result[1]
        except socket.herror:
            return None


if __name__ == '__main__':
    # unit test code.
    base_domain = ".google.com"
    d = "subdomains.txt"
    dictionary = []
    with open(d,"r") as f:
        dictionary = f.read().splitlines()
    
    
    mydns_reconassiance = DNSSearch(dictionary)
    dns_reconassiance_results = mydns_reconassiance.dns_serach(base_domain, True)
    for ip in dns_reconassiance_results:
        print(ip, dns_reconassiance_results[ip])

# for google
'''
142.251.45.36 ['www']
172.217.14.174 ['www4']
142.251.33.4 ['www5', 'www6']
142.251.32.174 ['www9', 'web', 'email']
142.250.113.83 ['mail']
142.250.113.19 ['mail']
142.250.113.18 ['mail']
142.250.113.17 ['mail']
142.251.32.169 ['blog']
216.239.32.10 ['ns', 'ns1']
216.239.34.10 ['ns2']
216.239.36.10 ['ns3']
216.239.38.10 ['ns4']
142.250.113.26 ['smtp']
142.250.113.27 ['smtp']
142.250.115.26 ['smtp']
142.250.115.27 ['smtp']
142.250.114.26 ['smtp']
142.251.33.46 ['admin']
64.9.224.68 ['vpn']
64.9.224.69 ['vpn']
64.9.224.70 ['vpn']
8.8.8.8 ['dns']
8.8.4.4 ['dns']
172.217.1.142 ['support']
142.250.113.138 ['cloud']
142.250.113.139 ['cloud']
142.250.113.113 ['cloud']
142.250.113.100 ['cloud']
142.250.113.101 ['cloud']
142.250.113.102 ['cloud']
172.217.1.228 ['api']
 '''