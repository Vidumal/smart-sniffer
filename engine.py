import threading
from scapy.all import sniff, IP, Raw

class PacketEngine:
    def __init__(self, ui_callback):
        self.ui_callback = ui_callback
        self.running = False
        self.packet_list = []

    def start_sniffing(self):
        self.running = True
        self.sniff_thread = threading.Thread(target=self._sniff)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def _sniff(self):
        sniff(prn=self._handle_packet, stop_filter=lambda x: not self.running, store=0)

    def _handle_packet(self, pkt):
        if IP in pkt:
            pkt_data = {
                "id": len(self.packet_list),
                "time": pkt.time,
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
                "proto": pkt[IP].proto,
                "length": len(pkt),
                "info": pkt.summary(),
                "raw": pkt,
                "risk": "Low"
            }
            if pkt.haslayer(Raw):
                payload = str(pkt[Raw].load).lower()
                if any(word in payload for word in ["user", "pass", "login", "config"]):
                    pkt_data["risk"] = "HIGH"

            self.packet_list.append(pkt_data)
            self.ui_callback(pkt_data)

    def stop(self):
        self.running = False