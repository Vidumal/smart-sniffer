import threading
import time
from scapy.all import sniff, IP, TCP, Raw

class PacketEngine:
    def __init__(self, ui_callback):
        self.ui_callback = ui_callback
        self.running = False
        self.packet_list = []
        self.current_filter = ""
        
        # Nmap Port Scan Tracker
        self.scan_tracker = {}
        self.SCAN_THRESHOLD = 10 

    def start_sniffing(self, bpf_filter=""):
        self.running = True
        self.current_filter = bpf_filter
        self.sniff_thread = threading.Thread(target=self._sniff)
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def _sniff(self):
        # We now pass the custom filter from the UI into Scapy
        try:
            sniff(filter=self.current_filter, prn=self._handle_packet, stop_filter=lambda x: not self.running, store=0)
        except Exception as e:
            print(f"Filter Error: {e}") # Catches invalid filter typing

    def _handle_packet(self, pkt):
        if IP in pkt:
            src_ip = pkt[IP].src
            current_time = time.time()
            risk_level = "Low"

            # Nmap Detection Logic
            if TCP in pkt:
                if pkt[TCP].flags == "S":
                    dst_port = pkt[TCP].dport
                    if src_ip not in self.scan_tracker:
                        self.scan_tracker[src_ip] = {"ports": set(), "time": current_time}
                    
                    if current_time - self.scan_tracker[src_ip]["time"] > 10:
                        self.scan_tracker[src_ip] = {"ports": set(), "time": current_time}
                        
                    self.scan_tracker[src_ip]["ports"].add(dst_port)
                    
                    if len(self.scan_tracker[src_ip]["ports"]) > self.SCAN_THRESHOLD:
                        risk_level = "🔴 NMAP SCAN DETECTED"

            # Plaintext Credential Logic
            if pkt.haslayer(Raw):
                payload = str(pkt[Raw].load).lower()
                if any(word in payload for word in ["user", "pass", "login", "config"]):
                    risk_level = "⚠️ HIGH (Creds)"

            pkt_data = {
                "id": len(self.packet_list),
                "time": pkt.time,
                "src": src_ip,
                "dst": pkt[IP].dst,
                "proto": pkt[IP].proto,
                "length": len(pkt),
                "info": pkt.summary(),
                "raw": pkt,
                "risk": risk_level
            }

            self.packet_list.append(pkt_data)
            self.ui_callback(pkt_data)

    def stop(self):
        self.running = False