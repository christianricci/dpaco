import time
import logging
from multiprocessing import Process, Queue
from api import Api
from fw import Fw

if __name__ == '__main__':
  queue = Queue()
  dpca = Api(queue)
  api = Process(target=dpca.run, args=())
  api.start()

  time.sleep(5)

  dpc = Fw(queue)
  fw = Process(target=dpc.run, args=())
  fw.start()

  fw.join()
  api.join()
