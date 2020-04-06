from netfilterqueue import NetfilterQueue
from scapy.all import *
import sqlite3
import re
import logging
import time
import json
import sys
import traceback
import requests
import dns.resolver
import pdb

# Analize packet, decide and populate runtime_cache
# level:
#   ALLOW-ALL-WEBSITES - accept packet to all websites
#   DROP-ALL-WEBSITES - drop packet from any websites
#   ACCESS-LEVEL-0 - accept websites with access level 0 = School related websites
#   ACCESS-LEVEL-1 - accept websites with access level 0,1 = Popular Content (video, music, etc) + Social Media (facebook, instagram, tiktok, etc)
#   ACCESS-LEVEL-2 - accept websites with access level 0,1,2 = Restricted and inappropiate websites

class DnsParentControlFw(object):
    def __init__(self, queue):
        self.log_level = 'INFO'
        # UI Server
        self.api_uri = '127.0.0.1:5000'
        # Lan Network preffic (first 3 octets)
        self.lan_network_preffix = '192.168.1.'
        # OpenDNS name server resolvers
        self.odns_nameserver_resolvers = ['208.67.222.222', '208.67.220.220']
        # https://support.opendns.com/hc/en-us/articles/227986927-What-are-the-Cisco-Umbrella-Block-Page-IP-Addresses-
        self.odns_content_category_block_page_ip = '146.112.61.106'
        # ACCESS-LEVEL-0 - accept websites with access level 0 = School related websites
        self.default_access_level = 0
        # ACCESS-LEVEL-3 - accept websites with access level 0,1,2 = Restricted and inappropiate websites
        self.default_max_access_level = 2
        # Process queue message
        self.msg_queue = queue
        # Handle Cache
        self.dns_cache = {}
        self.access_level_cache = {}
        self.runtime_cache = {}
        # Load Cache
        logging.info('[FW][Info] Initialize: loading cache %s', self.__class__.__name__)
        self.load_cache('dns_cache')
        self.load_cache('access_level_cache')
        logging.info('[FW][Info] Initialize: Started %s', self.__class__.__name__)

    def load_cache(self, cache_name):
        if cache_name == 'dns_cache':
            # load dns cache
            dns_names = self.api_request(request_type='get', namespace='dns-names')
            if dns_names:
                for row in dns_names:
                    ip_address = row['dns_query_ip']
                    del row['dns_query_ip']            
                    self.dns_cache[ip_address] = row

        if cache_name == 'access_level_cache':
            # load access_level cache
            levels = self.api_request(request_type='get', namespace='devices')
            if levels:
                for row in levels:
                    ip_address = row['ip_address']
                    del row['ip_address']
                    self.access_level_cache[ip_address] = row

    def clean_cache(self, cache_name):
        try:
            if cache_name == 'access_level_cache':
                self.access_level_cache.clear()
                self.load_cache('access_level_cache')
            if cache_name == 'dns_cache':
                self.dns_cache.clear()
                self.load_cache('dns_cache')
            if cache_name == 'runtime_cache':
                self.runtime_cache.clear()
        except BaseException as e:
            logging.error("[FW][Error] CACHE: <cache_name=%s>", cache_name)
            traceback.print_exc()

    def add_dns_cache(self, ip, row):
        self.dns_cache[ip] = row

    def api_request(self, **kwargs):
        request_type = kwargs.get('request_type')
        body = kwargs.get('body')
        namespace = kwargs.get('namespace')
        url = "http://" + self.api_uri + "/" + namespace
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

        if request_type == 'post':
            r = requests.post(url, data=body, headers=headers)
        elif request_type == 'delete':
            requests.delete(url, data=body, headers=headers)
            return None
        else:
            r = requests.get(url, headers=headers)
        return r.json()

    def dns_analyzer(self, dns_answer, raw_pkt):
        try:
            raw_pkt.accept()
            # Build DNS Tree
            full_dns_list = ''
            for x in range(dns_answer[DNS].ancount):
                rrname = dns_answer[DNSRR][x].rrname
                rdata = dns_answer[DNSRR][x].rdata
                full_dns_list += (rrname.decode('utf8') if type(rrname) == bytes else rrname) + ':' + \
                    (rdata.decode('utf8') if type(rdata) == bytes else rdata)
                if (x + 1) < dns_answer[DNS].ancount:
                    full_dns_list += '|'
            # Add to Cache and save into db
            re_c = re.compile(r'[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*')
            for ip in list(filter(re_c.search, [alias.split(':')[-1] for alias in full_dns_list.split('|')])):
                if ip.__contains__(self.lan_network_preffix):
                    continue
                # Associate the IP with the top CNAME
                dns_query_name = full_dns_list.split(':')[0]
                if not self.dns_cache.get(ip) or self.dns_cache.get(ip) != dns_query_name:
                    level = self.opendns_checker(dns_query_name)
                    count = self.dns_cache.get(ip)['count'] + 1 if self.dns_cache.get(ip) else 1
                    values = '{{"dns_query_name": "{dns_query_name}","dns_query_ip": "{dns_query_ip}",\
                                "full_dns_alias_tree": "{full_dns_alias_tree}","level": {level},"count": {count}}}'\
                             .format(dns_query_name=dns_query_name,
                                     dns_query_ip=ip,
                                     full_dns_alias_tree=full_dns_list,
                                     level=level,
                                     count=count)
                    self.add_dns_cache(ip, json.loads(values))
                    # Update Database every 5 repetitions
                    if count == 1 or count % 5 == 0:
                        if self.api_request(request_type='post', body=values, namespace='dns-names'):
                            logging.info("[FW][Info] DNS LOG: fqdn=%s requested by %s", dns_query_name, self.dst)
        except BaseException as e:
            logging.error("[FW][Error] DNS LOG: <src=%s>, <dst=%s> <rrname=%s> <rdata=%s> message: %s",
                self.src, self.dst, rrname, rdata, str(e))
            traceback.print_exc()

    def web_analyzer(self, web_request, raw_pkt):
        try:
            # Process existing action in runtime_cache
            runtime_key = str(self.src + '<->' + self.dst + ':' + self.dstport)
            if runtime_key in self.runtime_cache.keys():
                if self.runtime_cache[runtime_key] == 'accept':
                    raw_pkt.accept()
                    return
                elif self.runtime_cache[runtime_key] == 'drop':
                    raw_pkt.drop()
                    return
                else:
                    raw_pkt.drop()
                    return
            # Accept if destination is Local Lan
            if self.dst.__contains__(self.lan_network_preffix):
                raw_pkt.accept()
                return
            # Check the user access level against the dst ip level
            access_level_key = self.access_level_cache.get(self.src)
            dns = self.dns_cache.get(self.dst)
            if not dns:
                # Handle when request that doesn't have a DNS, example direct IP request
                dns_query_name = 'unknown_dns_name'
                count = 1
                values = '{{"dns_query_name": "{dns_query_name}","dns_query_ip": "{dns_query_ip}",\
                         "full_dns_alias_tree": "{full_dns_alias_tree}","level": {level},"count": {count}}}'\
                            .format(dns_query_name=dns_query_name,
                                    dns_query_ip=self.dst,
                                    full_dns_alias_tree=dns_query_name,
                                    level=self.default_access_level,
                                    count=count)
                self.add_dns_cache(self.dst, json.loads(values))
                # Update Database every 5 repetitions
                if count == 1 or count % 5 == 0:
                    if self.api_request(request_type='post', body=values, namespace='dns-names'):
                        logging.info("[FW][Info] DNS LOG: fqdn=%s requested by %s", dns_query_name, self.dst)
                dns = self.dns_cache.get(self.dst)
		
            if access_level_key:
                desc_key = access_level_key.get('owner') + " - " + access_level_key.get('device')
                if access_level_key.get('level') >= dns.get('level'):
                    raw_pkt.accept()
                    self.runtime_cache[runtime_key] = 'accept'
                    logging.info("[FW][Info] WEB LOG: accept,(%s) <fqdn=%s,fqdn_level=%s,src=%s> <user_level=%s>", 
                        desc_key, dns.get('dns_query_name'), dns.get('level'), runtime_key, access_level_key.get('level'))
                    return 
                else:
                    raw_pkt.drop()
                    self.runtime_cache[runtime_key] = 'drop'
                    logging.info("[FW][Info] WEB LOG: drop,(%s) <fqdn=%s,fqdn_level=%s,src=%s> <user_level=%s>",
                        desc_key, dns.get('dns_query_name'), dns.get('level'), runtime_key, access_level_key.get('level'))
                    return

            # if host not in access_level then it is allowed
            raw_pkt.accept()
            self.runtime_cache[runtime_key] = 'accept'
            logging.info("[FW][Info] WEB LOG: accept,(Other host) <fqdn=%s,fqdn_level=%s,src=%s> <user_level=4>",
                dns.get('dns_query_name'), dns.get('level'), runtime_key)
        except BaseException as e:
            logging.error("[FW][Error] WEB LOG: <runtime_key=%s>, <access_level_key=%s> <dns=%s> message: %s",
                runtime_key, access_level_key, dns, str(e))
            traceback.print_exc()

    def packet_decider(self, raw_pkt):
        if not (self.msg_queue is None) and not self.msg_queue.empty():
            self.process_msg_action()
        packet = IP(raw_pkt.get_payload())
        self.src = packet.src
        self.dst = packet.dst
        self.srcport = str(packet.payload.sport)
        self.dstport = str(packet.payload.dport)

        if self.log_level == 'DEBUG':
            logging.debug("[FW][Debug] -> %s:%s, %s:%s",
                self.src, self.srcport, self.dst, self.dstport)

        if packet and DNS in packet and self.srcport == '53':
            self.dns_analyzer(packet, raw_pkt)
        if packet and (self.dstport == '80' or self.dstport == '443'):
            self.web_analyzer(packet, raw_pkt)

    def process_msg_action(self):
        while not self.msg_queue.empty():
            msg = self.msg_queue.get()
            logging.info("[FW][Info]: received message <%s>", msg)
            if msg['action'] == 'clean_access_level_cache':
                logging.info("[FW][Info]: processing msg from [API] <action=%s>", msg['action'])
                self.load_cache('access_level_cache')
            elif msg['action'] == 'clean_runtime_cache':
                logging.info("[FW][Info]: processing msg from [API] <action=%s>", msg['action'])
                self.load_cache('access_level_cache')
                self.runtime_cache = {}
            else:
                logging.error("[FW][Error]: not able to match any action from msg <action=%s>", msg)

    def opendns_checker(self, name):
        level = self.default_access_level
        # OpenDNS nameservers
        resolver = dns.resolver.Resolver()
        resolver.nameservers = self.odns_nameserver_resolvers
        try:
            answer = resolver.query(name, 'a')[0].to_text().__contains__(self.odns_content_category_block_page_ip)
            if answer:
                level = self.default_max_access_level
                logging.info('[FW][Info] %s rejected by OpenDNS, set level to %s', name, level)
        except BaseException as e:
            logging.error("[FW][Error] while resolving %s", name)
            traceback.print_exc()
        return level

    def run(self):
        nfqueue = NetfilterQueue()
        nfqueue.bind(0, self.packet_decider)
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            logging.info("[FW][Info] Finishing nfqueue")
        nfqueue.unbind()
        self.close()

# Main
# if __name__ == "__main__":
#     format = "%(asctime)s: %(message)s"
#     logging.basicConfig(format=format, level=logging.INFO,
#                         datefmt="%H:%M:%S")
#     logging.info("%s starting", __file__)
#     dpc = DnsParentControlFw(None)
#     dpc.run()
#     logging.info("%s finishing", __file__)
