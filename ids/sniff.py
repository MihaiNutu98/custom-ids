from scapy.all import AsyncSniffer, TCP, IP
from datetime import datetime

def handle(pkt):
    if TCP in pkt and IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        flags = pkt[TCP].flags
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] {src} -> {dst} | TCP flags: {flags}")

sniffer = AsyncSniffer(prn=handle, store=False, filter="tcp")
sniffer.start()
print("Sniffer started. Press Ctrl+C to stop.")

sniffer.join()

