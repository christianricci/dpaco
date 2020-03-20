from netfilterqueue import NetfilterQueue
from scapy.all import *
import sqlite3
import re
# https://realpython.com/intro-to-python-threading/
import logging
import threading
import time

# Get all the DNS Answers coming from surce port 53
# iptables - A INPUT - p udp - -sport 53 - j NFQUEUE - -queue-num 0 - -queue-bypass

class DnsParentControl(object):
    sqlite_file = '/tmp/pcontrol.sqlite'
    dns_table_name = 'dns_query_tab'
    log_table_name = 'log_tab'

    def __init__(self):
        self.conn, self.cursor = self.connect()

    def connect(self):
        conn = sqlite3.connect(self.sqlite_file)
        c = conn.cursor()
        c.execute('DROP TABLE IF EXISTS {tn}'.format(tn=self.dns_table_name))
        c.execute('CREATE TABLE IF NOT EXISTS {tn} ( \
                    dns_query_name text, \
                    dns_query_ip text, \
                    full_dns_alias_tree text, \
                    PRIMARY KEY(dns_query_name, dns_query_ip))'
                  .format(tn=self.dns_table_name))
        c.execute('DROP TABLE IF EXISTS {tn}'.format(tn=self.log_table_name))
        c.execute('CREATE TABLE IF NOT EXISTS {tn} ( \
                    src text, \
                    srcport text, \
                    dst text, \
                    dstport text, \
                    haddr text)'
                  .format(tn=self.log_table_name))
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

    def dns_analyzer(self, dns_answer):
        full_dns_list = ''
        if dns_answer and DNS in dns_answer:
            for x in range(dns_answer[DNS].ancount):
                rrname = dns_answer[DNSRR][x].rrname
                rdata = dns_answer[DNSRR][x].rdata
                full_dns_list += (rrname.decode('utf8') if type(rrname) == bytes else rrname) + ':' + \
                    (rdata.decode('utf8') if type(rdata) == bytes else rdata)
                if (x + 1) < dns_answer[DNS].ancount:
                    full_dns_list += '|'
            re_c = re.compile(r'[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*')
            for ip in list(filter(re_c.search, [alias.split(':')[-1] for alias in full_dns_list.split('|')])):
                values = "'{dns_query_name}','{dns_query_ip}','{full_dns_alias_tree}'"\
                    .format(dns_query_name=full_dns_list.split(':')[0],
                            dns_query_ip=ip,
                            full_dns_alias_tree=full_dns_list)
                self.add_row(values, self.dns_table_name)
                logging.info("# DNS: %s", values)
                values = "'{src}','{srcport}','{dst}','{dstport}','{haddr}'"\
                    .format(src=self.src,
                            srcport=self.srcport,
                            dst=self.dst,
                            dstport=self.dstport,
                            haddr=self.haddr)
                self.add_row(values, self.log_table_name)
                logging.info("# LOG: %s", values)

    def packet_decider(self, pkt):
        packet = IP(pkt.get_payload())
        self.src = packet.src
        self.dst = packet.dst
        self.srcport = packet.payload.sport
        self.dstport = packet.payload.dport
        hw = pkt.get_hw()
        self.haddr = ''
        if hw and type(hw[0]) != int:
            haddr = ":".join("{:02x}".format(ord(c)) for c in hw[0:6])

        self.dns_analyzer(packet)
        pkt.accept()

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
