from netfilterqueue import NetfilterQueue
from scapy.all import *
import sqlite3
import re

def print_and_accept(pkt):
    packet = IP(pkt.get_payload())
    src = packet.src
    dstport = packet[UDP].dport
    hw = pkt.get_hw()
    haddr = ''
    if hw and type(hw[0]) != int:
        haddr = ":".join("{:02x}".format(ord(c)) for c in hw[0:6])

    dns_answer = packet
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
            add_row(cursor, values, dns_table_name)
            print('# DNS: ', values)
            values = "'{src}','{haddr}'"\
                .format(src=src,
                        haddr=haddr)
            add_row(cursor, values, log_table_name)
            print('# LOG: ', values)
    pkt.accept()

def connect(sqlite_file):
    conn = sqlite3.connect(sqlite_file)
    c = conn.cursor()
    c.execute('DROP TABLE IF EXISTS {tn}'.format(tn=dns_table_name))
    c.execute('CREATE TABLE IF NOT EXISTS {tn} ( \
                dns_query_name text, \
                dns_query_ip text, \
                full_dns_alias_tree text, \
                PRIMARY KEY(dns_query_name, dns_query_ip))'\
              .format(tn=dns_table_name))
    c.execute('DROP TABLE IF EXISTS {tn}'.format(tn=log_table_name))
    c.execute('CREATE TABLE IF NOT EXISTS {tn} ( \
                src text, \
                dst text, \
                dstport text, \
                log_text text)'\
              .format(tn=log_table_name))
    return conn, c

def close(conn):
    conn.close()

def add_row(cursor, values, table_name):
    try:
        cursor.execute('INSERT INTO {tn} values ({values})'.format(
            tn=table_name, values=values))
    except sqlite3.IntegrityError:
        pass
    conn.commit()

sqlite_file = '/tmp/pcontrol.sqlite'
dns_table_name = 'dns_query_tab'
log_table_name = 'log_tab'
conn, cursor = connect(sqlite_file)

nfqueue = NetfilterQueue()
nfqueue.bind(0, print_and_accept)

try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()
close(conn)
