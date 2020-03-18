from netfilterqueue import NetfilterQueue
from scapy.all import *
import sqlite3
import re

def print_and_accept(pkt):
    scapy_pkt = IP(pkt.get_payload())
    src = scapy_pkt.src  # source IP address
    dst = scapy_pkt.dst
    dns_answer = scapy_pkt
    full_dns_list = ''
    if dns_answer and DNS in dns_answer:
        for x in range(dns_answer[DNS].ancount):
            rrname = dns_answer[DNSRR][x].rrname
            rdata = dns_answer[DNSRR][x].rdata
            full_dns_list += (rrname.decode('utf8') if type(rrname) == bytes else rrname) + ':' + \
                (rdata.decode('utf8') if type(rdata) == bytes else rdata)
            if (x + 1) < dns_answer[DNS].ancount:
                full_dns_list += '|'
        hw = pkt.get_hw()
        haddr = ''
        if hw and type(hw[0]) != int:
            haddr = ":".join("{:02x}".format(ord(c)) for c in hw[0:6])

        pkt.accept()

        re_c = re.compile(r'[0-9]*\.[0-9]*\.[0-9]*\.[0-9]*')
        for ip in list(filter(re_c.search, [alias.split(':')[-1] for alias in full_dns_list.split('|')])):
            values = "'{src}','{dst}','{haddr}','{dns_query_name}','{dns_query_ip}','{full_dns_alias_tree}'"\
                .format(src=src,
                        dst=dst,
                        haddr=haddr,
                        dns_query_name=full_dns_list.split(':')[0],
                        dns_query_ip=ip,
                        full_dns_alias_tree=full_dns_list)
            add_row(cursor, values)
            print(values)

def connect(sqlite_file, table_name):
    """ Make connection to an SQLite database file """
    conn = sqlite3.connect(sqlite_file)
    c = conn.cursor()
    c.execute('DROP TABLE IF EXISTS {tn}'.format(tn=table_name))
    c.execute('CREATE TABLE IF NOT EXISTS {tn} (src text, dst text, haddr text, dns_query_name text, \
               dns_query_ip text, full_dns_alias_tree text, PRIMARY KEY(src, dst, haddr, dns_query_name, dns_query_ip))' \
              .format(tn=table_name))
    return conn, c

def close(conn):
    """ Commit changes and close connection to the database """
    # conn.commit()
    conn.close()

def add_row(cursor, values):
    try:
        cursor.execute('INSERT INTO {tn} values ({values})'.format(tn=table_name, values=values))
    except sqlite3.IntegrityError:
        pass
    conn.commit()

sqlite_file = '/tmp/pcontrol.sqlite'
table_name = 'dns_query_tab'
conn, cursor = connect(sqlite_file, table_name)

nfqueue = NetfilterQueue()
nfqueue.bind(0, print_and_accept)

try:
    nfqueue.run()
except KeyboardInterrupt:
    print('')

nfqueue.unbind()
close(conn)
