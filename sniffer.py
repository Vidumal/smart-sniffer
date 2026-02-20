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

    def _run_sniffing(self):
        sniff(prn=self._process_packet, stop_filter=lambda x: not self.running, store=0)

    def _process_packet(self, pkt):
        if IP in pkt:
            data = {
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
                "proto": pkt[IP].proto,
                "summary": pkt.summary()
            }
            if pkt.haslayer(Raw):
                payload = str(pkt[Raw].load)
                if any(kw in payload.lower() for kw in ["user", "pass", "login"]):
                    data["alert"] = "⚠️ CREDENTIALS DETECTED"
                else:
                    data["alert"] = ""
            
            self.callback(data)