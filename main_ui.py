import customtkinter as ctk
from sniffer_engine import SnifferEngine

class SnifferApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Network Guardian")
        self.geometry("900x600")
        ctk.set_appearance_mode("dark")

      
        self.start_btn = ctk.CTkButton(self, text="Start Capture", command=self.start_sniffing, fg_color="green")
        self.start_btn.pack(pady=10)

        
        self.display = ctk.CTkTextbox(self, width=850, height=450)
        self.display.pack(padx=20, pady=10)

        self.engine = SnifferEngine(self.update_ui)

    def start_sniffing(self):
        self.display.insert("end", "[*] Starting Sniffing...\n")
        self.engine.start()
        self.start_btn.configure(text="Capture Running...", state="disabled")
    
    def update_ui(self, data):
        alert_str = f" | {data['alert']}" if data['alert'] else ""
        entry = f"[{data['src']}] -> [{data['dst']}] | Proto: {data['proto']}{alert_str}\n"
        self.display.insert("end", entry)
        self.display.see("end")

if __name__ == "__main__":
    app = SnifferApp()
    app.mainloop()