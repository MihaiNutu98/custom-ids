from scapy.all import AsyncSniffer, TCP, IP
from datetime import datetime
from storage import init_db, insert_alert

init_db()  # create table if not exists

def handle(pkt):
    if TCP in pkt and IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        flags = pkt[TCP].flags
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] {src} -> {dst} | TCP flags: {flags}")
        # insert a test alert into SQLite
        insert_alert(src, dst, "TCP", "test_alert", f"Saw TCP packet with flags {flags}")

sniffer = AsyncSniffer(prn=handle, store=False, filter="tcp")
sniffer.start()
print("Sniffer started. Press Ctrl+C to stop.")

sniffer.join()


