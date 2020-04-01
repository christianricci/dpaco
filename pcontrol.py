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
import pdb

class DnsParentControlFw(object):
    def __init__(self, queue):
        self.api_uri = '127.0.0.1:5000'
        self.log_level = 'INFO'
        self.default_access_level = 2
        self.dns_cache = {}
        self.access_level_cache = {}
        self.runtime_cache = {}
        self.msg_queue = queue
        logging.info('[FW][Info] Initialize: Starting %s', self.__class__.__name__)
        # pdb.set_trace()

    def load_cache(self, cache_name):
        if cache_name == 'dns_cahe':
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
        else:
            r = requests.get(url, headers=headers)
        return r.json()

    def dns_analyzer(self, dns_answer, raw_pkt):
        try:
            raw_pkt.accept()

            full_dns_list = ''
            for x in range(dns_answer[DNS].ancount):
                rrname = dns_answer[DNSRR][x].rrname
                rdata = dns_answer[DNSRR][x].rdata
                full_dns_list += (rrname.decode('utf8') if type(rrname) == bytes else rrname) + ':' + \
                    (rdata.decode('utf8') if type(rdata) == bytes else rdata)
                if (x + 1) < dns_answer[DNS].ancount:
                    full_dns_list += '|'
            re_c = re.compile(r'[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*')
            for ip in list(filter(re_c.search, [alias.split(':')[-1] for alias in full_dns_list.split('|')])):
                if not ip in self.dns_cache.keys():
                    values = '{{"dns_query_name": "{dns_query_name}","dns_query_ip": "{dns_query_ip}","full_dns_alias_tree": "{full_dns_alias_tree}","level": {level}}}'\
                        .format(dns_query_name=full_dns_list.split(':')[0],
                                dns_query_ip=ip,
                                full_dns_alias_tree=full_dns_list,
                                level=self.default_access_level)
                    dns_name = self.api_request(request_type='post', body=values, namespace='dns-names')
                    del dns_name['dns_query_ip']
                    self.add_dns_cache(ip, dns_name)
                    logging.info("[FW][Info] DNS LOG: fqdn=%s requested by %s",
                                 dns_name['dns_query_name'], self.dst)
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

            # Analize packet, decide and populate runtime_cache
            # level:
            #   ALLOW-ALL-WEBSITES - accept packet to all websites
            #   DROP-ALL-WEBSITES - drop packet from any websites
            #   ACCESS-LEVEL-0 - accept websites with access level 0 = School related websites
            #   ACCESS-LEVEL-1 - accept websites with access level 0,1 = Popular Content (video, music, etc)
            #   ACCESS-LEVEL-2 - accept websites with access level 0,1,2 = Social Media (facebook, instagram, tiktok, etc)
            #   ACCESS-LEVEL-3 - accept websites with access level 0,1,2,3 = Restricted and inappropiate websites
            #
            access_level_key = self.access_level_cache.get(self.src)
            dns = self.dns_cache.get(self.dst)
            if not dns:
                values = '{{"dns_query_name": "{dns_query_name}","dns_query_ip": "{dns_query_ip}","full_dns_alias_tree": "{full_dns_alias_tree}","level": {level}}}'\
                    .format(dns_query_name='unknown_dns_name',
                            dns_query_ip=self.dst,
                            full_dns_alias_tree='unknown_dns_name',
                            level=self.default_access_level)                
                dns_name = self.api_request(request_type='post', body=values, namespace='dns-names')
                del dns_name['dns_query_ip']
                self.add_dns_cache(self.dst ,dns_name)
                logging.info(
                    "[FW][Info] DNS LOG: fqdn=%s requested by %s", 'unknown_dns_name', self.dst)
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

    def run(self):
        self.load_cache('dns_cache')
        self.load_cache('access_level_cache')
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
