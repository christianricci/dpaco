class Fw:
  def __init__(self, queue):
    self.queue = queue

  def receive(self):
    while not self.queue.empty():
      print(self.queue)
      print(self.queue.get())

  def run(self):
    self.receive()
