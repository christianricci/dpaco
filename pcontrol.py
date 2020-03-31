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

class DnsParentControl(object):
    def __init__(self, log_level = 'INFO'):
        self.api_uri = '127.0.0.1:5000'
        self.log_level = log_level
        self.default_access_level = 2
        self.dns_cache = {}
        self.access_level_cache = {}
        self.runtime_cache = {}
        self.load_cache('dns_cache')
        self.load_cache('access_level_cache')

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
            logging.error("[Error] CACHE: <cache_name=%s>", cache_name)
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
                    logging.info("# DNS LOG: fqdn=%s requested by %s", dns_name['dns_query_name'], self.dst)
        except BaseException as e:
            logging.error("[Error] DNS LOG: <src=%s>, <dst=%s> <rrname=%s> <rdata=%s> message: %s",
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
            #   ACCESS-LEVEL-0 - accept websites with access level 0 only = School related websites
            #   ACCESS-LEVEL-1 - accept websites with access level 1 only = Popular Content (video, music, etc)
            #   ACCESS-LEVEL-2 - accept websites with access level 2 only = Social Media (facebook, instagram, tiktok, etc)
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
                logging.info("# DNS LOG: fqdn=%s requested by %s", 'unknown_dns_name', self.dst)
                dns = self.dns_cache.get(self.dst)
		
            if access_level_key:
                desc_key = access_level_key.get('owner') + " - " + access_level_key.get('device')
                if access_level_key.get('level') >= dns.get('level'):
                    raw_pkt.accept()
                    self.runtime_cache[runtime_key] = 'accept'
                    logging.info("# WEB LOG: accept,(%s) <fqdn=%s,fqdn_level=%s,src=%s> <user_level=%s>", 
                        desc_key, dns.get('dns_query_name'), dns.get('level'), runtime_key, access_level_key.get('level'))
                    return 
                else:
                    raw_pkt.drop()
                    self.runtime_cache[runtime_key] = 'drop'
                    logging.info("# WEB LOG: drop,(%s) <fqdn=%s,fqdn_level=%s,src=%s> <user_level=%s>", 
                        desc_key, dns.get('dns_query_name'), dns.get('level'), runtime_key, access_level_key.get('level'))
                    return
            # if host not in access_level then it is allowed
            raw_pkt.accept()
            self.runtime_cache[runtime_key] = 'accept'
            logging.info("# WEB LOG: accept,(Other host) <fqdn=%s,fqdn_level=%s,src=%s> <user_level=4>",
                dns.get('dns_query_name'), dns.get('level'), runtime_key)
        except BaseException as e:
            logging.error("[Error] WEB LOG: <runtime_key=%s>, <access_level_key=%s> <dns=%s> message: %s",
                runtime_key, access_level_key, dns, str(e))
            traceback.print_exc()

    def packet_decider(self, raw_pkt):
        packet = IP(raw_pkt.get_payload())
        self.src = packet.src
        self.dst = packet.dst
        self.srcport = str(packet.payload.sport)
        self.dstport = str(packet.payload.dport)

        if self.log_level == 'DEBUG':
            logging.debug("-> DEBUG: %s:%s, %s:%s",
                self.src, self.srcport, self.dst, self.dstport)

        if packet and DNS in packet and self.srcport == '53':
            self.dns_analyzer(packet, raw_pkt)
        if packet and (self.dstport == '80' or self.dstport == '443'):
            self.web_analyzer(packet, raw_pkt)

    def run(self):
        nfqueue = NetfilterQueue()
        nfqueue.bind(0, self.packet_decider)
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            logging.info("Finishing nfqueue")
        nfqueue.unbind()
        self.close()

if __name__ == "__main__":
    format = "%(asctime)s: %(message)s"
    logging.basicConfig(format=format, level=logging.INFO,
                        datefmt="%H:%M:%S")
    logging.info("%s starting", __file__)
    dpc = DnsParentControl()
    dpc.run()
    logging.info("%s finishing", __file__)
