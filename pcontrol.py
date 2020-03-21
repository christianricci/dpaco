from netfilterqueue import NetfilterQueue
from scapy.all import *
import sqlite3
import re
# https://realpython.com/intro-to-python-threading/
import logging
import threading
import time

# Get all the DNS Answers coming from surce port 53
# iptables - A INPUT -p udp -sport 53 - j NFQUEUE - -queue-num 0 - -queue-bypass
# Get all sport 80, 443 requests reponding to browser request 
# iptables -A INPUT -p tcp -m multiport -sports 80, 443 -j NFQUEUE -queue-num 0 -queue-bypass

class DnsParentControl(object):
    sqlite_file = '/tmp/pcontrol.sqlite'
    dns_table_name = 'dns_query_tab'
    log_table_name = 'log_tab'
    blacklist_table_name = 'blacklist_tab'

    def __init__(self):
        self.conn, self.cursor = self.connect()
        self.dns_cache = {}
        self.blacklist_cache = {}
        self.runtime_cache = {}
        self.load_cache()

    def connect(self):
        conn = sqlite3.connect(self.sqlite_file)
        c = conn.cursor()
        # c.execute('DROP TABLE IF EXISTS {tn}'.format(tn=self.dns_table_name))
        c.execute('CREATE TABLE IF NOT EXISTS {tn} ( \
                    dns_query_name text, \
                    dns_query_ip text, \
                    full_dns_alias_tree text, \
                    PRIMARY KEY(dns_query_name, dns_query_ip))'
                  .format(tn=self.dns_table_name))
        # c.execute('DROP TABLE IF EXISTS {tn}'.format(tn=self.log_table_name))
        c.execute('CREATE TABLE IF NOT EXISTS {tn} ( \
                    src text, \
                    srcport text, \
                    dst text, \
                    dstport text, \
                    haddr text)'
                  .format(tn=self.log_table_name))
        c.execute('CREATE TABLE IF NOT EXISTS {tn} ( \
                    name text, \
                    haddr text, \
                    mode text)'
                  .format(tn=self.blacklist_table_name))
        return conn, c

    def add_row(self, values, table_name):
        try:
            self.cursor.execute('INSERT INTO {tn} values ({values})'
                                .format(tn=table_name, values=values))
        except sqlite3.IntegrityError:
            pass
        self.conn.commit()

    def close(self):
        self.conn.close()

    def load_cache(self):
        # load dns cache
        self.cursor.execute('SELECT dns_query_ip, dns_query_name FROM {tn}'
                            .format(tn=self.dns_table_name))
        rows = self.cursor.fetchall()
        for row in rows:
            self.dns_cache[row[0]] = row[1]
        # load blacklist cache
        self.cursor.execute('SELECT haddr, name||":"||mode FROM {tn}'
                            .format(tn=self.blacklist_table_name))
        rows = self.cursor.fetchall()
        self.blacklist_cache['ALL_HOSTS'] = 'ALLOW-ALL-WEBSITES'
        self.blacklist_cache['UNKNOWN_HOST'] = 'ALLOW-ALL-WEBSITES'
        for row in rows:
            self.blacklist_cache[row[0]] = row[1]

    def add_dns_cache(self, ip, fqdn):
        self.dns_cache[ip] = fqdn

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
                self.add_dns_cache(ip, full_dns_list.split(':')[0])
                self.add_row(values, self.dns_table_name)
                logging.info("# DNS: %s", values)
                values = "'{src}','{srcport}','{dst}','{dstport}','{haddr}'"\
                    .format(src=self.src,
                            srcport=self.srcport,
                            dst=self.dst,
                            dstport=self.dstport,
                            haddr=self.haddr)
                self.add_row(values, self.log_table_name)
                logging.info("# DNS LOG: %s", values)

    def web_analyzer(self, web_request, raw_pkt):
        # Process existing action in runtime_cache
        runtime_key = str(self.src + ':' + self.srcport + '<->' + self.haddr)
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
        # mode:
        #   ALLOW-ALL-WEBSITES - accept all websites
        #
        action_key = self.blacklist_cache.get(self.haddr)
        if action_key == 'ALLOW-ALL-WEBSITES':
            raw_pkt.accept()
            self.runtime_cache[runtime_key] = 'accept'
            logging.info("# WEB LOG: %s = %s", runtime_key, action_key)
            return 
        if action_key == 'DROP-ALL-WEBSITES':
            raw_pkt.drop()
            self.runtime_cache[runtime_key] = 'drop'
            logging.info("# WEB LOG: %s = %s", runtime_key, action_key)
            return
        else:
            raw_pkt.drop()
            self.runtime_cache[runtime_key] = 'accept'
            logging.info("# WEB LOG: %s = %s", runtime_key, 'ALLOW-ALL-WEBSITES')
                
    def packet_decider(self, raw_pkt):
        packet = IP(raw_pkt.get_payload())
        self.src = packet.src
        self.dst = packet.dst
        self.srcport = str(packet.payload.sport)
        self.dstport = str(packet.payload.dport)
        hw = raw_pkt.get_hw()
        self.haddr = 'UNKNOWN_HOST'
        if hw:
            place = ("%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBBBB", raw_pkt.get_hw())).split(':')
            self.haddr = ":".join(place[i] for i in range(len(place)-2))

        if packet and DNS in packet:
            self.dns_analyzer(packet, raw_pkt)
        if packet and TCP in packet and (packet.sport == 80 or packet.sport == 443):
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
