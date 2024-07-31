import tkinter as tk
from tkinter import messagebox
import nmap

class ScanMeTool:
    def __init__(self, root):
        self.root = root
        self.root.title("ScanMe Tool")
        self.root.geometry("600x400")

        self.label = tk.Label(root, text="Enter IP Address or Hostname:")
        self.label.pack(pady=10)

        self.entry = tk.Entry(root, width=40)
        self.entry.pack(pady=10)

        # Define the scan_button with command=self.scan AFTER defining the scan method
        self.scan_button = tk.Button(root, text="Scan", command=self.scan)
        self.scan_button.pack(pady=10)

        self.result_text = tk.Text(root, width=80, height=15)
        self.result_text.pack(pady=10)

    def scan(self):
        target = self.entry.get()
        if not target:
            messagebox.showerror("Input Error", "Please enter a valid IP address or hostname.")
            return

        try:
            nm = nmap.PortScanner()
            nm.scan(target, arguments='-sV')

            self.result_text.delete(1.0, tk.END)

            for host in nm.all_hosts():
                self.result_text.insert(tk.END, f'Host : {host} ({nm[host].hostname()})\n')
                self.result_text.insert(tk.END, f'State : {nm[host].state()}\n')

                for proto in nm[host].all_protocols():
                    self.result_text.insert(tk.END, f'Protocol : {proto}\n')
                    lport = nm[host][proto].keys()

                    for port in sorted(lport):
                        self.result_text.insert(tk.END, f'Port : {port}\tState : {nm[host][proto][port]["state"]}\n')

        except nmap.nmap.PortScannerError as e:
            messagebox.showerror("Scan Error", f"Nmap error: {str(e)}")
        except Exception as e:
            messagebox.showerror("Scan Error", f"Unexpected error: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ScanMeTool(root)
    root.mainloop()
