import tkinter as tk
from tkinter import ttk, filedialog
import customtkinter as ctk
from engine import PacketEngine
from intelligence import get_ip_location, get_org_owner
import matplotlib.pyplot as plt
from scapy.all import wrpcap
import threading

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class WiresharkPro(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Smart Sniffer | Network Intelligence")
        self.geometry("1200x750")

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # --- LEFT SIDEBAR (Controls) ---
        self.sidebar = ctk.CTkFrame(self, width=200, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(7, weight=1) # Pushes export button to the bottom

        self.logo_label = ctk.CTkLabel(self.sidebar, text="SMART\nSNIFFER", font=ctk.CTkFont(size=24, weight="bold"))
        self.logo_label.grid(row=0, column=0, padx=20, pady=(30, 10))
        
        self.status_label = ctk.CTkLabel(self.sidebar, text="Status: IDLE", text_color="gray", font=ctk.CTkFont(size=12))
        self.status_label.grid(row=1, column=0, padx=20, pady=(0, 10))

        self.filter_entry = ctk.CTkEntry(self.sidebar, placeholder_text="e.g. tcp port 80")
        self.filter_entry.grid(row=2, column=0, padx=20, pady=(0, 20), sticky="ew")
        self.filter_entry.insert(0, "not arp and not port 443")

        self.start_btn = ctk.CTkButton(self.sidebar, text="▶ Start Capture", command=self.start_capture, fg_color="#27ae60", hover_color="#2ecc71")
        self.start_btn.grid(row=3, column=0, padx=20, pady=10)

        self.stop_btn = ctk.CTkButton(self.sidebar, text="■ Stop Capture", command=self.stop_capture, fg_color="#c0392b", hover_color="#e74c3c", state="disabled")
        self.stop_btn.grid(row=4, column=0, padx=20, pady=10)

        self.stats_btn = ctk.CTkButton(self.sidebar, text="📊 Show Stats", command=self.show_stats, fg_color="transparent", border_width=2, text_color=("gray10", "#DCE4EE"))
        self.stats_btn.grid(row=5, column=0, padx=20, pady=10)

        # NEW: Auto-Scroll Toggle
        self.autoscroll_var = tk.BooleanVar(value=True)
        self.autoscroll_cb = ctk.CTkCheckBox(self.sidebar, text="Auto-Scroll", variable=self.autoscroll_var, fg_color="#2980b9")
        self.autoscroll_cb.grid(row=6, column=0, padx=20, pady=10)

        self.export_btn = ctk.CTkButton(self.sidebar, text="💾 Export PCAP", command=self.export_pcap, fg_color="#2980b9", hover_color="#3498db")
        self.export_btn.grid(row=8, column=0, padx=20, pady=30) 

        # --- RIGHT MAIN AREA (Data) ---
        self.main_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=10, pady=10)
        self.main_frame.grid_rowconfigure(0, weight=3) 
        self.main_frame.grid_rowconfigure(1, weight=1) 
        self.main_frame.grid_columnconfigure(0, weight=1)

        self.tree_frame = ctk.CTkFrame(self.main_frame, corner_radius=10)
        self.tree_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 10))

        # NEW: Add the CustomTkinter Scrollbar
        self.tree_scroll = ctk.CTkScrollbar(self.tree_frame)
        self.tree_scroll.pack(side="right", fill="y", pady=2)

        # Link the Scrollbar to the Treeview
        self.tree = ttk.Treeview(self.tree_frame, columns=("No.", "Source", "Destination", "Location", "Owner", "Risk"), show='headings', yscrollcommand=self.tree_scroll.set)
        self.tree_scroll.configure(command=self.tree.yview)

        self.style_treeview()

        for col in self.tree["columns"]:
            self.tree.heading(col, text=col)
            self.tree.column(col, minwidth=100, width=150, anchor="center", stretch=True)
            
        self.tree.column("Location", width=200, stretch=True)
        self.tree.column("Owner", width=200, stretch=True)
        # Added padx to give the scrollbar some breathing room
        self.tree.pack(fill="both", expand=True, padx=(2, 0), pady=2)
        self.tree.bind("<<TreeviewSelect>>", self.show_details)

        self.detail_view = ctk.CTkTextbox(self.main_frame, corner_radius=10, font=ctk.CTkFont(family="Consolas", size=12))
        self.detail_view.grid(row=1, column=0, sticky="nsew")
        self.detail_view.insert("1.0", "Select a packet to view raw dissect details here...")

        self.engine = PacketEngine(self.add_to_table)

    def style_treeview(self):
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", background="#2b2b2b", foreground="white", rowheight=30, fieldbackground="#2b2b2b", borderwidth=0, font=('Helvetica', 10))
        style.map('Treeview', background=[('selected', '#1f538d')])
        style.configure("Treeview.Heading", background="#1f1f1f", foreground="white", relief="flat", font=('Helvetica', 10, 'bold'))
        style.map("Treeview.Heading", background=[('active', '#343638')])
        
        self.tree.tag_configure('nmap_alert', foreground='#ff4d4d') 
        self.tree.tag_configure('high_alert', foreground='#ffcc00') 

    def start_capture(self):
        self.status_label.configure(text="Status: 🔴 SNIFFING", text_color="#e74c3c")
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.engine.start_sniffing(bpf_filter=self.filter_entry.get())

    def stop_capture(self):
        self.status_label.configure(text="Status: ⏸ PAUSED", text_color="#f1c40f")
        self.engine.stop()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")

    def add_to_table(self, data):
        self.after(0, self._insert_placeholder, data)
        threading.Thread(target=self._fetch_intelligence, args=(data,), daemon=True).start()

    def _insert_placeholder(self, data):
        tags = ()
        if "NMAP" in data.get("risk", ""): tags = ('nmap_alert',)
        elif "HIGH" in data.get("risk", ""): tags = ('high_alert',)

        self.tree.insert("", "end", iid=data["id"], values=(data["id"], data["src"], data["dst"], "Looking up...", "Looking up...", data["risk"]), tags=tags)
        
        # NEW: Only Auto-Scroll if the checkbox is ticked!
        if self.autoscroll_var.get():
            self.tree.yview_moveto(1)

    def _fetch_intelligence(self, data):
        location = get_ip_location(data["dst"])
        owner = get_org_owner(data["dst"])
        self.after(0, self._update_row, data["id"], location, owner)

    def _update_row(self, item_id, location, owner):
        try:
            current_values = self.tree.item(item_id, "values")
            if current_values:
                new_values = (current_values[0], current_values[1], current_values[2], location, owner, current_values[5])
                self.tree.item(item_id, values=new_values)
        except Exception:
            pass 

    def show_details(self, event):
        if not self.tree.selection(): return
        selected_item = self.tree.selection()[0]
        pkt_obj = self.engine.packet_list[int(selected_item)]["raw"]
        self.detail_view.delete("1.0", "end")
        self.detail_view.insert("1.0", pkt_obj.show(dump=True))

    def show_stats(self):
        if not self.engine.packet_list: return
        
        counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "Other": 0}
        for pkt in self.engine.packet_list:
            if pkt["proto"] == 6: counts["TCP"] += 1
            elif pkt["proto"] == 17: counts["UDP"] += 1
            elif pkt["proto"] == 1: counts["ICMP"] += 1
            else: counts["Other"] += 1

        labels = [k for k, v in counts.items() if v > 0]
        sizes = [v for k, v in counts.items() if v > 0]

        if not sizes: return

        plt.figure(figsize=(6,4))
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', colors=['#3498db', '#e74c3c', '#f1c40f', '#95a5a6'][:len(labels)])
        plt.title(f"Traffic Distribution ({len(self.engine.packet_list)} Packets)")
        plt.show()

    def export_pcap(self):
        if not self.engine.packet_list: return
        filepath = filedialog.asksaveasfilename(defaultextension=".pcap", filetypes=[("PCAP", "*.pcap")], title="Save Capture")
        if filepath:
            wrpcap(filepath, [p["raw"] for p in self.engine.packet_list])

if __name__ == "__main__":
    app = WiresharkPro()
    app.mainloop()