import threading
from scapy.all import sniff, IP, TCP, Raw


class SnifferEngine:
    def __init__(self, callback):
        self.callback = callback
        self.running = False

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._run_sniffing)
        self.thread.daemon = True
        self.thread.start()
    
    def stop(self):
        self.running = False
    
    