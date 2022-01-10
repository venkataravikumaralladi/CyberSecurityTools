# -*- coding: utf-8 -*-
"""
Created on Mon Dec 27 15:11:58 2021

@author: Venkata Ravi Kumar A

This script demonstration of using the vole db API to convert our knowledge of our 
target system hopefully into exploitable vulnerabilities that we can take advantage of
to attack system.

References:
    https://vuldb.com/?kb.api
    https://github.com/vuldb/vuldb-api-python-examples
"""

import requests

with open('vuldb_api_key.txt', 'r') as f:
  vuldb_key = f.read()

def vuldb_lookup(product, version=None):
    url = 'https://vuldb.com/?api'

    if version:
        prod_details = 'product=%s,version:%s' % (product, version)
    else:
        prod_details = 'product:%s' % product

    # we are using advanced search as it allows us to specify product name and version number
    query = { 'apikey':vuldb_key,
              'advancedsearch':prod_details
    }
    print('cve_lookup.py::vuldb_lookup cve_lookup : query is ', query)
    response = requests.post(url, query)
    cve_json = response.json()
    if 'result' in cve_json:
        sources = [result['source'] for result in cve_json['result'] if 'source' in result]
        return sources
    else:
        return []
    

if __name__ == '__main__':
    # unit test code.
    # we can use the information we got from service_lookup.py and use this for example we got
    # {'port': 2087, 'product': 'HTTP', 'version': '1.1'}
    vulnerabilities_http_1_1 = vuldb_lookup('HTTP', '1.1')
    for vul in vulnerabilities_http_1_1:
        print(vul)
    print('Use above CVE\' information to get potential attack vectors')
    print()
    print('If there are no CVE\'s we can do crenditial stuffing')
        
'''
Sample out put looks like below:
    
    {'cve': {'id': 'CVE-2021-45710'}}
    {'cve': {'id': 'CVE-2021-45706'}}
    {'cve': {'id': 'CVE-2018-25028'}}
    {'cve': {'id': 'CVE-2018-25027'}}
    {'cve': {'id': 'CVE-2021-45471'}}
    {'cve': {'id': 'CVE-2021-45474'}}
    {'cve': {'id': 'CVE-2021-45473'}}
    {'cve': {'id': 'CVE-2021-45472'}}
    {'cve': {'id': 'CVE-2020-20598'}}
    {'cve': {'id': 'CVE-2020-20597'}}
    {'cve': {'id': 'CVE-2020-20595'}}
    {'cve': {'id': 'CVE-2021-44544'}}
    {'cve': {'id': 'CVE-2021-44471'}}
    {'cve': {'id': 'CVE-2021-31558'}}
    {'cve': {'id': 'CVE-2021-23228'}}
    {'cve': {'id': 'CVE-2021-36886'}}
    {'cve': {'id': 'CVE-2021-36885'}}
    {'cve': {'id': 'CVE-2021-45267'}}
    {'cve': {'id': 'CVE-2021-45266'}}
    {'cve': {'id': 'CVE-2021-45263'}}
    {'cve': {'id': 'CVE-2021-45262'}}
    {'cve': {'id': 'CVE-2021-45260'}}
    {'cve': {'id': 'CVE-2021-45259'}}
    {'cve': {'id': 'CVE-2021-45258'}}
    {'cve': {'id': 'CVE-2021-39013'}}
    {'cve': {'id': 'CVE-2021-44927'}}
    {'cve': {'id': 'CVE-2021-44925'}}
    {'cve': {'id': 'CVE-2021-44924'}}
    {'cve': {'id': 'CVE-2021-44923'}}
    {'cve': {'id': 'CVE-2021-44922'}}
    {'cve': {'id': 'CVE-2021-44921'}}
    {'cve': {'id': 'CVE-2021-44920'}}
    {'cve': {'id': 'CVE-2021-44918'}}
    {'cve': {'id': 'CVE-2021-43851'}}
    {'cve': {'id': 'CVE-2021-44874'}}
    {'cve': {'id': 'CVE-2021-36337'}}
    {'cve': {'id': 'CVE-2021-44876'}}
    {'cve': {'id': 'CVE-2021-44875'}}
    {'cve': {'id': 'CVE-2021-44877'}}
    {'cve': {'id': 'CVE-2012-20001'}}
    {'cve': {'id': 'CVE-2021-24907'}}
    {'cve': {'id': 'CVE-2021-24846'}}
    {'cve': {'id': 'CVE-2021-43847'}}
    {'cve': {'id': 'CVE-2021-43750'}}
    {'cve': {'id': 'CVE-2021-43749'}}
    {'cve': {'id': 'CVE-2021-43748'}}
    {'cve': {'id': 'CVE-2021-36887'}}
    {'cve': {'id': 'CVE-2021-43747'}}
    {'cve': {'id': 'CVE-2021-43029'}}
    {'cve': {'id': 'CVE-2021-43028'}}

'''