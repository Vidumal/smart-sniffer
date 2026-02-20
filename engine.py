import threading
from scapy.all import sniff, IP, TCP, UDP, Raw
import queue

class PacketEngine:
    def __init__(self, ui_callback):
        self.ui_callback = ui_callback
        self.running = False
        self.packet_list = []

    def start_sniffing(self, interface=None):
        self.running = True
        self.sniff_thread = threading.Thread(target=self._sniff)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()