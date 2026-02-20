import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from engine import PacketEngine


class WiresharkPro(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SLIIT Cyber-Sniffer v1.0")
        self.geometry("1100x700")
        
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