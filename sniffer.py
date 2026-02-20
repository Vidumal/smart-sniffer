import threading
from scapy.all import sniff, IP, TCP, Raw


class SnifferEngine:
    def __init__(self, callback):
        self.callback = callback
        self.running = False