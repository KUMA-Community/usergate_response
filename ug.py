#!/usr/bin/python3

import argparse
import xmlrpc.client as rpc
import json
import os

parser = argparse.ArgumentParser()

subparser = parser.add_subparsers(dest='command')
subparser.required=True

blockurl = subparser.add_parser('blockurl')
blockdomain = subparser.add_parser('blockdomain')
blockip = subparser.add_parser('blockip')

blockurl.add_argument('-i', '--item', type=str, help='Provide URL for block by UserGate', required=True)
blockurl.add_argument('-r', '--rule_name', type=str, default='KUMA Block Suspicious URLs', help='Provide name for content rule (Default: "KUMA Block Suspicious URLs")')
blockurl.add_argument('-l', '--list_name', type=str, default='KUMA Suspicious URLs', help='Provide name for URL list (Default: "KUMA Suspicious URLs")')

blockdomain.add_argument('-i', '--item', type=str, help='Provide Domain for block by UserGate', required=True)
blockdomain.add_argument('-r', '--rule_name', type=str, default='KUMA Block Suspicious Domains', help='Provide name for firewall rule (Default: "KUMA Block Suspicious Domains")')
blockdomain.add_argument('-l', '--list_name', type=str, default='KUMA Suspicious Domains', help='Provide name for Domain list (Default: "KUMA Suspicious Domains")')

blockip.add_argument('-i', '--item', type=str, help='Provide IP for block by UserGate', required=True)
blockip.add_argument('-r', '--rule_name', type=str, default='KUMA Block Suspicious IPs', help='Provide name for firewall rule (Default: "KUMA Block Suspicious IPs")')
blockip.add_argument('-l', '--list_name', type=str, default='KUMA Suspicious IPs', help='Provide name for Domain list (Default: "KUMA Suspicious IPs")')

args=parser.parse_args()

action=args.command
item=args.item
rule_name=args.rule_name
list_name=args.list_name

param_file_path = os.path.dirname(os.path.abspath(__file__)) + '/ug.json'

with open(param_file_path, 'r') as param_file:
    params = json.load(param_file)

server = 'http://' + params['host'] + ':4040/rpc'

s = rpc.ServerProxy(server)

login = params['username']
password = params['password']

#get auth token for future requests
auth_token = s.v2.core.login(login, password,{'origin': 'dev-script'})['auth_token'] 

list_item=[{"value":item}]

list_type="url"
list_id_type="urllist_id"

if (action=='blockip'):

    list_type="network"
    list_id_type="list_id"

nlist=s.v2.nlists.list(auth_token, list_type, 0, 10000, {"search":list_name})['items']

if(len(nlist)==0):

    nlist_id=s.v2.nlists.add(auth_token, {"type":list_type, "name":list_name})

else:

    nlist_id=nlist[0]['id']

s.v2.nlists.list.add.items(auth_token, nlist_id, list_item) 

position_id={"position":1}
enabled={"enabled":True}

if (action!='blockurl'):

    rule=s.v1.firewall.rules.list(auth_token,0,1000,{"name":rule_name})['items']

    if(len(rule)==0):
        rule_default={'name': rule_name,  'action': 'drop', 'position': 1, 'dst_ips': [[list_id_type, nlist_id]], 'enabled': True}

        s.v1.firewall.rule.add(auth_token, rule_default)
    else: 
        rule_id=rule[0]['id']

        s.v1.firewall.rule.update(auth_token,rule_id,{'dst_ips': [[list_id_type, nlist_id]]})
        s.v1.firewall.rule.update(auth_token, rule_id, position_id)
        s.v1.firewall.rule.update(auth_token, rule_id, enabled)
else:
    rule=s.v1.content.rules.list(auth_token,0,1000,{"name":rule_name})['items']

    if(rule[0]['id']==-1):
        rule_default={'name': rule_name,  'action': 'drop', 'position': 1,'urls': [nlist_id], 'enabled': True}

        s.v1.content.rule.add(auth_token,rule_default)

    else:
        rule_id=rule[0]['id']

        s.v1.content.rule.update(auth_token, rule_id,{'urls': [nlist_id]})     
        s.v1.content.rule.update(auth_token, rule_id, position_id)
        s.v1.content.rule.update(auth_token, rule_id, enabled)


