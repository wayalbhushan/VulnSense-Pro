import scapy.all as scapy
from scapy.layers import dns, http
import math
import re
import argparse
import pandas as pd
import psutil
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.align import Align

console = Console()

class VulnSensePro:
    def __init__(self, interface, save_results=False):
        self.interface = interface
        self.save_results = save_results
        self.events = []
        self.stats = {"DNS_EXFIL": 0, "JWT": 0, "AWS_KEY": 0, "CRED": 0, "DATA_BURST": 0}
        self.start_time = datetime.now()
        self.sensitive_patterns = {
            "JWT": r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*",
            "AWS_KEY": r"AKIA[0-9A-Z]{16}",
            "CRED": r"(?i)(user|pass|login|pwd|token|auth)=([^& \n\r]+)"
        }

    def calculate_entropy(self, data):
        if not data: return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(chr(x))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def make_layout(self) -> Layout:
        layout = Layout()
        layout.split(
            Layout(name="header", size=3),
            Layout(name="main", ratio=1),
            Layout(name="footer", size=3)
        )
        layout["main"].split_row(
            Layout(name="side", size=35),
            Layout(name="body")
        )
        return layout

    def generate_header(self) -> Panel:
        return Panel(Align.center(Text("VULNSENSE PRO v3.5 - ENTERPRISE NETWORK AUDITOR", style="bold white on blue")), style="blue")

    def generate_stats_panel(self) -> Panel:
        stats_table = Table.grid(expand=True)
        cpu = psutil.cpu_percent()
        ram = psutil.virtual_memory().percent
        
        stats_table.add_row(f"[cyan]CPU Usage:[/cyan]  [{'green' if cpu < 50 else 'red'}]{cpu}%[/{'green' if cpu < 50 else 'red'}]")
        stats_table.add_row(f"[cyan]RAM Usage:[/cyan]  {ram}%")
        stats_table.add_row(f"[cyan]Uptime:[/cyan]     {str(datetime.now() - self.start_time).split('.')[0]}")
        stats_table.add_row("-" * 25)
        
        for key, val in self.stats.items():
            style = "bold red" if val > 0 else "dim green"
            stats_table.add_row(f"[white]{key.ljust(12)}:[/white] [{style}]{val}[/{style}]")
        
        return Panel(stats_table, title="[bold]AUDIT CORE STATUS[/bold]", border_style="bright_blue")

    def generate_main_table(self) -> Table:
        table = Table(expand=True, border_style="dim")
        table.add_column("TS", style="cyan", width=10)
        table.add_column("LVL", width=8)
        table.add_column("TYPE", style="magenta", width=12)
        table.add_column("SOURCE IP", style="green", width=15)
        table.add_column("RECON/DATA", style="white")

        for event in self.events[-15:]:
            lvl_color = "bold red" if event['level'] == "CRITICAL" else "bold yellow"
            table.add_row(event['ts'], f"[{lvl_color}]{event['level']}[/{lvl_color}]", event['type'], event['ip'], event['msg'])
        return table

    def process_packet(self, packet):
        # 1. DNS Exfiltration (Entropy)
        if packet.haslayer(dns.DNSQR):
            query = packet[dns.DNSQR].qname.decode('utf-8').rstrip('.')
            sub = query.split('.')[0]
            if self.calculate_entropy(sub) > 3.8 and len(sub) > 12:
                self.add_event("DNS_EXFIL", "CRITICAL", packet, f"Entropy Alert: {query[:25]}...")
                self.stats["DNS_EXFIL"] += 1

        # 2. HTTP Credentials / Leaks
        if packet.haslayer(http.HTTPRequest):
            url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load.decode(errors='ignore')
                for label, pattern in self.sensitive_patterns.items():
                    if re.search(pattern, payload):
                        self.add_event(label, "HIGH", packet, f"Leak at: {url[:25]}...")
                        self.stats[label] += 1
        
        # 3. Data Burst Detection
        if len(packet) > 1400:
            self.stats["DATA_BURST"] += 1

        return None

    def add_event(self, e_type, level, packet, msg):
        src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "Local"
        self.events.append({
            "ts": datetime.now().strftime("%H:%M:%S"),
            "level": level, "type": e_type, "ip": src_ip, "msg": msg
        })

    def start(self):
        layout = self.make_layout()
        layout["header"].update(self.generate_header())
        layout["footer"].update(Panel(Align.center("[italic]Monitoring active... Press Ctrl+C to Stop and Export Report[/italic]"), style="dim"))

        with Live(layout, refresh_per_second=4, screen=True) as live:
            try:
                scapy.sniff(
                    iface=self.interface, 
                    store=0, 
                    prn=lambda x: (
                        self.process_packet(x),
                        layout["side"].update(self.generate_stats_panel()),
                        layout["body"].update(self.generate_main_table())
                    )[0],
                    filter="udp port 53 or tcp port 80"
                )
            except KeyboardInterrupt:
                if self.save_results:
                    filename = f"audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                    pd.DataFrame(self.events).to_csv(filename, index=False)
                    console.print(f"\n[bold green][+] Exported: {filename}[/bold green]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", default="eth0")
    parser.add_argument("-s", "--save", action="store_true")
    args = parser.parse_args()

    auditor = VulnSensePro(interface=args.interface, save_results=args.save)
    auditor.start()