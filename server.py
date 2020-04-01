import time
import logging
from pcontrol_api import DnsParentControlApi
from pcontrol import DnsParentControlFw
from multiprocessing import Process, Queue
import pdb

if __name__ == '__main__':
  format = "%(asctime)s: %(message)s"
  logging.basicConfig(format=format, level=logging.INFO,
                      datefmt="%H:%M:%S")

  queue = Queue()

  dpca = DnsParentControlApi(queue)
  api = Process(target=dpca.run, args=())
  api.start()

  DnsParentControlFw(queue).run()
