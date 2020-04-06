import dns.resolver
import re
import logging
import traceback
import pdb

class DnsParentControlFw(object):
  def __init__(self):
    self.odns_content_category_block_page_ip = '146.112.61.106'
    self.default_max_access_level = 3
    self.default_access_level = 0

  def opendns_checker(self, name):
    level = self.default_access_level
    # OpenDNS nameservers
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['208.67.222.222', '208.67.220.220']
    try:
      # pdb.set_trace()
      answer = resolver.query(name, 'a')[0].to_text().__contains__(self.odns_content_category_block_page_ip)
      if answer:
        logging.info('[FW][Info] %s rejected by OpenDNS, set level to %s', name, level)
        level = self.default_max_access_level
    except BaseException as e:
      logging.error("[FW][Error] resoving %s", name)
      traceback.print_exc()
    return level

format = "%(asctime)s: %(message)s"
logging.basicConfig(format=format, level=logging.INFO, datefmt="%H:%M:%S")

print(DnsParentControlFw().opendns_checker('www.youtube.com'))
