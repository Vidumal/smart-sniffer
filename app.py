import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from engine import PacketEngine
from intelligence import get_ip_location, get_org_owner
import matplotlib.pyplot as plt

class WiresharkPro(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SLIIT Cyber-Sniffer v1.0")
        self.geometry("1100x700")

        self.tree["columns"] = ("No.", "Source", "Destination", "Location", "Owner", "Risk")
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)

        self.toolbar = ctk.CTkFrame(self, height=50)
        self.toolbar.pack(fill="x", side="top", padx=5, pady=5)
        
        self.start_btn = ctk.CTkButton(self.toolbar, text="▶ Start", command=self.start_capture, width=80, fg_color="green")
        self.start_btn.pack(side="left", padx=5)
        
        self.stop_btn = ctk.CTkButton(self.toolbar, text="■ Stop", command=self.stop_capture, width=80, fg_color="red")
        self.stop_btn.pack(side="left", padx=5)

        self.table_frame = tk.Frame(self)
        self.table_frame.pack(fill="both", expand=True, padx=10)
        
        self.tree = ttk.Treeview(self.table_frame, columns=("No.", "Time", "Source", "Destination", "Protocol", "Risk"), show='headings')
        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=100)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.show_details)

        self.detail_view = ctk.CTkTextbox(self, height=200)
        self.detail_view.pack(fill="x", padx=10, pady=10)

        self.engine = PacketEngine(self.add_to_table)

        self.stats_btn = ctk.CTkButton(self.toolbar, text=" Show Stats", command=self.show_stats)
        self.stats_btn.pack(side="right", padx=10)

    def start_capture(self):
        self.engine.start_sniffing()
        self.start_btn.configure(state="disabled")

    def stop_capture(self):
        self.engine.stop()
        self.start_btn.configure(state="normal")

    def add_to_table(self, data):
        self.tree.insert("", "end", iid=data["id"], values=(data["id"], data["time"], data["src"], data["dst"], data["proto"], data["risk"]))
        location = get_ip_location(data["dst"])
        owner = get_org_owner(data["dst"])

        self.tree.insert("", "end", values=(data["id"], data["src"], data["dst"], location, owner, data["risk"]))

    def show_details(self, event):
        selected_item = self.tree.selection()[0]
        pkt_obj = self.engine.packet_list[int(selected_item)]["raw"]
        self.detail_view.delete("1.0", "end")
        self.detail_view.insert("1.0", pkt_obj.show(dump=True)) 

    def show_stats(self):
        
        protocols = ["TCP", "UDP", "ICMP", "Other"]
        counts = [15, 5, 2, 1] 
        
        plt.figure(figsize=(6,4))
        plt.pie(counts, labels=protocols, autopct='%1.1f%%', colors=['#3498db', '#e74c3c', '#f1c40f', '#95a5a6'])
        plt.title("Traffic Distribution")
        plt.show()

if __name__ == "__main__":
    app = WiresharkPro()
    app.mainloop()