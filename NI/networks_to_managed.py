#!/usr/bin/python

import httplib
import ssl
import json
import base64
import sys
import urllib

if not sys.version_info < (3,):
    sys.stderr.write("This script is written in python 2.\n")
    sys.exit(1)

grid_ip = raw_input('Grid Master IP: ')
user = raw_input('User: ')
password = raw_input('Password: ')

conn = httplib.HTTPSConnection(grid_ip, timeout=20, context=ssl._create_unverified_context())
auth = base64.encodestring('%s:%s' % (user, password))[:-1]
AUTH_HEADER = {'Authorization': 'Basic %s' % auth}

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
    return parsed

def print_and_read_options(opts):
    print '\n'.join('%s - %s' % (i, name) for i, name in enumerate(opts))
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

schema_url = 'https://%s/wapi/v1.0/?_schema&_return_type=json-pretty' % grid_ip
versions = read_wapi(conn, schema_url)
wapi_v = 'v' + versions['supported_versions'][-1] #get latest
wapi_url = 'https://%s/wapi/%s/' % (grid_ip, wapi_v)

nv_url = wapi_url + 'networkview?_return_type=json-pretty&_return_fields=name' 
nv_parsed = read_wapi(conn, nv_url)
network_views = [x["name"] for x in nv_parsed]
print '''You have %s network views configured on Grid.
Do you want to process all of them or select one?''' % len(network_views)
opt = print_and_read_options(['process all'] + network_views)
nv_lst = network_views if opt == 0 else [network_views[opt-1]]

mdp_url = wapi_url + 'discovery:memberproperties?_return_fields=discovery_member,scan_interfaces,role&_return_type=json-pretty'
mdp_parsed = read_wapi(conn, mdp_url)
nv_map = dict([(nv, []) for nv in network_views])
if any(x['role'] == 'DNP' for x in mdp_parsed):
    # we have probes!
    member_type = 'DNP'
else:
    member_type = 'DNM'
for mdp in mdp_parsed:
    if mdp['role'] != member_type:
        continue
    scan_itf = mdp['scan_interfaces']
    for iface in scan_itf:
        itf_nv = iface['network_view']
        if mdp['discovery_member'] not in nv_map[itf_nv]:
            nv_map[itf_nv].append(mdp['discovery_member'])


for nv in nv_lst:
    print '[%s]' % nv

    nw_params = urllib.urlencode({ 'network_view'  : nv
                                 , '_return_fields': 'network'
                                 , 'unmanaged'     : 'true'
                                 , '_return_type'  : 'json-pretty' })
    ipv4networks_url = wapi_url + 'network?' + nw_params
    unmanaged = read_wapi(conn, ipv4networks_url)
    ipv6networks_url = wapi_url + 'ipv6network?' + nw_params
    unmanaged += read_wapi(conn, ipv6networks_url)
    if len(unmanaged) == 0:
        print 'There\'s no unmanaged networks in %s network view, skipping' % nv
        continue
    else:
        print 'There\'s %s unmanaged networks in %s network view' % (len(unmanaged), nv)

    if len(nv_map[nv]) == 0:
        print 'No scan interfaces assigned to this network view, skipping'
        continue
    elif len(nv_map[nv]) == 1:
        discovery_member = nv_map[nv][0]
    else:
        print 'There\'s 2 discovery members assigned to "default" network view.'
        print 'Which one you want to use for discovery?'
        opt = print_and_read_options(['skip (member will be chosen automatically)'] + nv_map[nv])
        if opt != 0:
            discovery_member = nv_map[nv][opt-1]
        else:
            discovery_member = nv_map[nv][0]

    opt = raw_input('Do you want to leave some networks unmanaged? (y/N)')
    excluded_networks = []
    if opt == 'y':
        print 'Please, enumerate networks in form "address/CIDR -- e.g. 10.0.0.0/8" separating with commas:'
        excluded_networks = set(x.strip() for x in raw_input().split(', '))

    refs = [x['_ref'] for x in unmanaged if x['network'] not in excluded_networks]
    # begin multiupdate
    request_url = wapi_url + 'request'
    post_data = '[' + ', '.join(
        '''{
            "method": "PUT",
            "object": "''' + ref + '''",
            "data": {
                "unmanaged": false,
                "discovery_member": "''' + discovery_member + '''",
                "enable_discovery": true
            }
        }''' for ref in refs) + ']'
    conn.request('POST', request_url, post_data, AUTH_HEADER) # ignoring errors
    conn.getresponse().read() # makes httplib happy
    print 'Processing', nv, 'network view finished.'

print 'Completed!'
conn.close()
