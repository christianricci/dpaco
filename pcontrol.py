from netfilterqueue import NetfilterQueue
from scapy.all import *
import sqlite3
import re
import logging
import time
import json

# Get all the DNS Answers coming from surce port 53
# iptables -A INPUT -p udp -sport 53 -j NFQUEUE --queue-num 0 --queue-bypass
# Get all sport 80, 443 requests reponding to browser request 
# iptables -A OUTPUT -p tcp -m multiport -dports 80, 443 -j NFQUEUE -queue-num 0 -queue-bypass

class DnsParentControl(object):
    sqlite_file = '/tmp/pcontrol.sqlite'
    dns_table_name = 'dns_query_tab'
    access_level_table_name = 'access_level_tab'

    def __init__(self, log_level = 'INFO'):
        self.log_level = log_level
        self.default_access_level = 0
        self.conn, self.cursor = self.connect()
        self.dns_cache = {}
        self.access_level_cache = {}
        self.load_cache()
        self.runtime_cache = {}

    def connect(self):
        conn = sqlite3.connect(self.sqlite_file)
        c = conn.cursor()
        # c.execute('DROP TABLE IF EXISTS {tn}'.format(tn=self.dns_table_name))
        c.execute('CREATE TABLE IF NOT EXISTS {tn} ( \
                    dns_query_name text, \
                    dns_query_ip text, \
                    full_dns_alias_tree text, \
                    level int default 4, \
                    PRIMARY KEY(dns_query_name, dns_query_ip))'
                  .format(tn=self.dns_table_name))
        c.execute('CREATE TABLE IF NOT EXISTS {tn} ( \
                    description text, \
                    ip_address text, \
                    mac_address text, \
                    level int default 0)'
                  .format(tn=self.access_level_table_name))
        return conn, c

    def add_row(self, values, table_name):
        try:
            self.cursor.execute('INSERT INTO {tn} \
                (dns_query_name, dns_query_ip, full_dns_alias_tree) values ({values})'
                .format(tn=table_name, values=values))
        except sqlite3.IntegrityError:
            pass
        self.conn.commit()

    def close(self):
        self.conn.close()

    def load_cache(self):
        # load dns cache
        self.cursor.execute('SELECT dns_query_ip, dns_query_name, level FROM {tn}'
                            .format(tn=self.dns_table_name))
        rows = self.cursor.fetchall()
        for row in rows:
            self.dns_cache[row[0]] = json.loads('{"dns_query_name": "' + row[1] + '","level": ' + str(row[2]) + '}')
        # load access_level cache
        self.cursor.execute('SELECT ip_address, description, mac_address, level FROM {tn}'
                            .format(tn=self.access_level_table_name))
        rows = self.cursor.fetchall()
        for row in rows:
            self.access_level_cache[row[0]] = json.loads('{"desc": "' + row[1] +
                                                           '", "mac_address": "' + row[2] +
                                                           '", "level": ' + str(row[3]) + '}')

    def add_dns_cache(self, ip, row):
        self.dns_cache[ip] = json.loads(row)

    def dns_analyzer(self, dns_answer, raw_pkt):
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
                values = "'{dns_query_name}','{dns_query_ip}','{full_dns_alias_tree}'"\
                    .format(dns_query_name=full_dns_list.split(':')[0],
                            dns_query_ip=ip,
                            full_dns_alias_tree=full_dns_list)
                self.add_dns_cache(ip, 
                    '{"dns_query_name": "' + full_dns_list.split(':')[0] + '","level": ' + str(self.default_access_level) +'}')
                self.add_row(values, self.dns_table_name)
                logging.info("# DNS LOG: fqdn=%s requested by %s",
                    full_dns_list.split(':')[0],
                    self.dst)

    def web_analyzer(self, web_request, raw_pkt):
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
        if access_level_key:
            desc_key = access_level_key.get('desc')
            if access_level_key.get('level') >= dns.get('level'):
                raw_pkt.accept()
                self.runtime_cache[runtime_key] = 'accept'
                logging.info("# WEB LOG: accept,(%s) <fqdn=%s,fqdn_level=%s,src=%s> <user_level=%s>", desc_key,
                    dns.get('dns_query_name'), dns.get('level'), runtime_key, access_level_key.get('level'))
                return 
            else:
                raw_pkt.drop()
                self.runtime_cache[runtime_key] = 'drop'
                logging.info("# WEB LOG: drop,(%s) <fqdn=%s,fqdn_level=%s,src=%s> <user_level=%s>", desc_key,
                    dns.get('dns_query_name'), dns.get('level'), runtime_key, access_level_key.get('level'))
                return
        # if host not in access_level then it is allowed
        raw_pkt.accept()
        self.runtime_cache[runtime_key] = 'accept'
        logging.info("# WEB LOG: accept,(Other host) <fqdn=%s,fqdn_level=%s,src=%s> <user_level=4>",
            dns.get('dns_query_name'), dns.get('level'), runtime_key)

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
