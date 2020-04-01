import time

class Api:
  msg_queue = None

  def __init__(self, queue):
    Api.msg_queue = queue

  def send(self, i):
    print(Api.msg_queue)
    Api.msg_queue.put('msg#: ' + str(i) + ' - this is a message...')

  def run(self):
    for i in range(11):
      self.send(i)
      # time.sleep(2)
