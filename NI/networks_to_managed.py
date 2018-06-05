#!/usr/bin/python
# Copyright (c) 2018 Infoblox Inc. All Rights Reserved.
# version 1.0.1 2018-06-05

'''
networks_to_managed.py
'''

import httplib
import ssl
import json
import base64
import sys
import urllib
import argparse
import getpass

AUTH_HEADER = ''
error_flag = False


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
        global error_flag
        error_flag = True
        print parsed["Error"]
        return []
    return parsed


def print_and_read_options(opts):
    for i, name in enumerate(opts):
        print '%s - %s' % (i, name)
    print 'q - cancel and quite'
    opt = raw_input()
    while opt != 'q':
        try:
            i = int(opt)
            if 0 <= i < len(opts):
                return i
            else:
                raise ValueError
        except:
            print 'Incorrect input. Please, try again: '
            opt = raw_input()
    else:
        print 'Cancelled'
        sys.exit(0)


def main():
    if not sys.version_info < (3,):
        sys.stderr.write("This script is written in python 2.\n")
        sys.exit(1)

    global AUTH_HEADER

    # parser block
    parser = argparse.ArgumentParser(description="convert unmanaged networks "
                                                 "to managed networks")
    parser.add_argument("-buf", "--buffer",
                        type=int,
                        default=50,
                        help="number of unmanaged objects to be updated per "
                             "request")
    parser.add_argument("-nc", "--networkcontainer",
                        help="include network containers",
                        action="store_true")
    parser.add_argument("-e", "--exclude", help="allow to specify which "
                                                "unmanaged objects to exclude",
                        action="store_true")
    parser.add_argument("-v", "--verbosity", help="increase output verbosity",
                        action="store_true")
    args = parser.parse_args()

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

    # reading network views
    nv_url = wapi_url + \
        'networkview?_return_type=json-pretty&_return_fields=name'
    nv_parsed = read_wapi(conn, nv_url)

    # processing network view list
    network_views = [x["name"] for x in nv_parsed]
    print 'You have %s network views configured on Grid.\n' \
          'Do you want to process all of them or select one?' \
          % len(network_views)
    opt = print_and_read_options(['process all'] + network_views)
    nv_lst = network_views if opt == 0 else [network_views[opt-1]]

    # reading member discovery properties
    mdp_url = wapi_url + \
        'discovery:memberproperties?' \
        '_return_fields=discovery_member,scan_interfaces,role&' \
        '_return_type=json-pretty'
    mdp_parsed = read_wapi(conn, mdp_url)

    # searching for any DNP member
    nv_map = dict([(nv, []) for nv in network_views])
    if any(x['role'] == 'DNP' for x in mdp_parsed):
        # we have probes!
        member_type = 'DNP'
    else:
        member_type = 'DNM'

    # creating mapping network view - discovery member
    # by iterating scan interfaces of mdp
    for mdp in mdp_parsed:
        if mdp['role'] != member_type:
            continue
        scan_itf = mdp['scan_interfaces']
        for iface in scan_itf:
            itf_nv = iface['network_view']
            if mdp['discovery_member'] not in nv_map[itf_nv]:
                nv_map[itf_nv].append(mdp['discovery_member'])

    # iterating network view in map
    for nv in nv_lst:
        print '[%s]' % nv

        # check if this network view is assigned to any scan
        if len(nv_map[nv]) == 0:
            print 'No scan interfaces assigned to this network view, ' \
                  'skipping.'
            continue
        elif len(nv_map[nv]) == 1:
            discovery_member = nv_map[nv][0]
        else:
            # if > 1
            print 'There\'s %s discovery members ' \
                  'assigned to "%s" network view.' % (len(nv_map[nv]), nv)
            print 'Which one you want to use for discovery?'
            opt = print_and_read_options(
                ['skip (member will be chosen automatically)'] + nv_map[nv]
            )
            discovery_member = nv_map[nv][0] if opt == 0 else nv_map[nv][opt-1]

        # searching parameters for unmanaged objects
        nw_params = urllib.urlencode({'network_view': nv.encode('utf-8'),
                                      '_return_fields': 'network',
                                      'unmanaged': 'true',
                                      '_return_type': 'json-pretty'})

        # ... for unmanaged ipv4 networks
        ipv4network_url = wapi_url + 'network?' + nw_params
        unmanaged = read_wapi(conn, ipv4network_url)
        # ... for unmanaged ipv6 networks
        ipv6network_url = wapi_url + 'ipv6network?' + nw_params
        unmanaged += read_wapi(conn, ipv6network_url)
        # if need to include networkcontainers
        if args.networkcontainer:
            # ... for unmanaged ipv4 networkcontainers
            ipv4nc_url = wapi_url + 'networkcontainer?' + nw_params
            unmanaged += read_wapi(conn, ipv4nc_url)
            # ... for unmanaged ipv6 networkcontainers
            ipv6nc_url = wapi_url + 'ipv6networkcontainer?' + nw_params
            unmanaged += read_wapi(conn, ipv6nc_url)

        # checking unmanaged objects
        if len(unmanaged) == 0:
            print 'There\'s no unmanaged networks %s' \
                  'in "%s" network view, skipping.' % \
                  ((args.networkcontainer and 'and networkcontainers ' or ''),
                   nv)
            continue
        else:
            print 'There\'s %s unmanaged networks %s' \
                  'in "%s" network view.' % \
                  (len(unmanaged),
                   (args.networkcontainer and 'and networkcontainers ' or ''),
                   nv)

        if args.exclude:
            print args.exclude
            opt = raw_input(
                str("Do you want to leave some networks %sunmanaged? "
                    "(y/N) [N]:" %
                    (args.networkcontainer and 'and networkcontainers ' or ''))
            ) or "N"

            excluded_networks = []
            if opt == 'y':
                print 'Please, enumerate networks %sin form ' \
                      '"address/CIDR -- e.g. 10.0.0.0/8" separating with ' \
                      'commas:' % \
                      (args.networkcontainer and 'and networkcontainers ' or
                       '')
                excluded_networks = \
                    set(x.strip() for x in raw_input().split(', '))

            # filter unmanaged
            unmanaged = [x for x in unmanaged
                         if x['network'] not in excluded_networks]

        # begin multiupdate
        request_url = wapi_url + 'request'
        i = 0
        n = args.buffer  # process n networks per query
        post_data = ''
        while i*n < len(unmanaged):
            nw_slice = unmanaged[i*n:(i+1)*n]

            post_data += "["
            for nw in nw_slice:
                if args.verbosity:
                    print 'Processing %s: %s' %\
                          (nw['_ref'].split('/')[0], nw['network'])

                post_data += \
                    '''{
                        "method": "PUT",
                        "object": "''' + nw['_ref'] + '''",
                        "data": {
                            "unmanaged": false,
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
        print 'Processing "%s" network view finished.' % nv

    print 'Completed%s!' % (error_flag and ' with errors' or '')
    conn.close()

if __name__ == '__main__':
    main()
