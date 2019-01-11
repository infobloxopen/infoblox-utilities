#!/usr/bin/python
# Copyright (c) 2019 Infoblox Inc. All Rights Reserved.
# version 1.0.0 2019-01-11 

import httplib
import ssl
import json
import base64
import sys
import urllib
import argparse
import getpass
import os

AUTH_HEADER = ''


def read_wapi(conn, url):
    try:
        conn.request('GET', url, '', AUTH_HEADER)
    except Exception as e:
        print e
        sys.exit(1)
    data = conn.getresponse()
    resp = data.read()
    try:
        parsed = json.loads(resp)
    except:
        print data.status, data.reason
        sys.exit(1)
    if type(parsed) is dict and "Error" in parsed:
        print parsed["Error"]
        return []
    return parsed


def main():
    if not sys.version_info < (3,):
        sys.stderr.write("This script is written in python 2.\n")
        sys.exit(1)

    global AUTH_HEADER

    # parser block
    parser = argparse.ArgumentParser(
        description="Enable discovery for list of managed networks. "
                    "Networks should be enumerated in CIDR format "
                    "and be separated with newlines (see file 'example'). "
                    "Network containers are not supported"
    )
    parser.add_argument('network_view',
                        help="Name of the network view "
                             "in which networks should be processed. "
                             "This parameter is required because "
                             "the same CIDRs can exist "
                             "in different network views")
    parser.add_argument('file',
                        help="File containing list of networks "
                             "separated with newlines")
    parser.add_argument("-v", "--verbosity", help="increase output verbosity",
                        action="store_true")
    args = parser.parse_args()
    if not os.path.isfile(args.file):
        print 'Error: File %s does not exist' % args.file
        sys.exit(1)

    # appliance settings
    grid_ip = raw_input('Grid Master IP: ')
    user = raw_input('User: ')
    password = getpass.getpass('Password: ')

    # establishing connection to appliance
    conn = httplib.HTTPSConnection(grid_ip, timeout=120,
                                   context=ssl._create_unverified_context())
    auth = base64.encodestring('%s:%s' % (user, password))[:-1]
    AUTH_HEADER = {'Authorization': 'Basic %s' % auth}

    # reading available wapi schemas
    schema_url = 'https://%s/wapi/v1.0/?_schema&_return_type=json-pretty' \
                 % grid_ip
    versions = read_wapi(conn, schema_url)
    wapi_v = 'v' + versions['supported_versions'][-1]  # get latest

    # using the latest version of wapi
    wapi_url = 'https://%s/wapi/%s/' % (grid_ip, wapi_v)

    # processing networks list
    networks = open(args.file).readlines()
    networkview = args.network_view
    print 'Discovery will be enabled on %s networks in %s network view' % (
        len(networks), networkview)

    # reading member discovery properties
    mdp_url = wapi_url + \
        'discovery:memberproperties?' \
        '_return_fields=discovery_member,scan_interfaces,role&' \
        '_return_type=json-pretty'
    mdp_parsed = read_wapi(conn, mdp_url)

    # searching for any DNP member
    if any(x['role'] == 'DNP' for x in mdp_parsed):
        # we have probes!
        member_type = 'DNP'
    else:
        member_type = 'DNM'

    discovery_member = None
    for mdp in mdp_parsed:
        if mdp['role'] != member_type:
            continue
        scan_itf = mdp['scan_interfaces']
        for iface in scan_itf:
            if networkview == iface['network_view']:
                # found the discovery member
                discovery_member = mdp['discovery_member']
                break
        if discovery_member:
            break
    if not discovery_member:
        print ("Error: Network view have not been created yet "
               "or has no assigned scan interfaces")
        sys.exit(1)

    # begin multiupdate
    request_url = wapi_url + 'request'
    i = 0
    n = 50
    post_data = ''
    while i*n < len(networks):
        nw_slice = networks[i*n:(i+1)*n]

        post_data += "["
        for nw in nw_slice:
            nw = nw.strip()
            nw_params = urllib.urlencode({'network': nw,
                                          'network_view': networkview,
                                          '_return_fields': 'network',
                                          '_return_type': 'json-pretty'})
            subnets = []
            for obj in ('network?', 'ipv6network?'):
                subnets = read_wapi(conn, wapi_url + obj + nw_params)
                if subnets:
                    break
            if not subnets:
                print "\nSubnet %s does not exist in %s network view" % (
                    nw, networkview) 
                continue
            nw_ref = subnets[0]['_ref']
            if args.verbosity:
                print 'Processing %s: %s' %\
                      (nw['_ref'].split('/')[0], nw['network'])
            else:
                print '.',

            post_data += \
                '''{
                    "method": "PUT",
                    "object": "''' + nw_ref + '''",
                    "data": {
                        "use_enable_discovery": true,
                        "discovery_member": "''' + discovery_member + '''",
                        "enable_discovery": true
                    }
                },'''
        post_data = post_data[:-1] + ']'
        conn.request('POST', request_url,
                     post_data, AUTH_HEADER)  # ignoring errors
        conn.getresponse().read()  # makes httplib happy
        i += 1
        post_data = ''

    print 'Completed!'
    conn.close()

if __name__ == '__main__':
    main()
