from scapy.all import sniff, TCP, UDP, IP
from storage import insert_alert
import time
from collections import defaultdict, deque

# === CONFIGURATION ===
WINDOW_SECONDS = 10        # Sliding window duration
MAX_PORTS = 5              # Threshold for port scan
TRAFFIC_SPIKE_MULTIPLIER = 3  # Spike detection: current rate vs baseline
MIN_PACKETS_PER_WINDOW = 5     # Minimum packets to trigger spike

# Track TCP SYNs for port scan: (src, dst) -> deque of (port, timestamp)
syn_tracker = defaultdict(lambda: deque())
# Track UDP destination ports for port scan: (src, dst) -> deque of (port, timestamp)
udp_tracker = defaultdict(lambda: deque())
# Track packet counts per window for anomaly detection
packet_counts = deque()  # Each entry: (timestamp, count)
baseline_rate = 1        # Initial dummy baseline

def handle_packet(pkt):
    global baseline_rate

    if IP not in pkt:
        return

    src = pkt[IP].src
    dst = pkt[IP].dst
    now = time.time()

    # Count packet for traffic spike detection
    packet_counts.append(now)
    # Remove old entries outside the window
    while packet_counts and packet_counts[0] < now - WINDOW_SECONDS:
        packet_counts.popleft()
    current_rate = len(packet_counts) / WINDOW_SECONDS

    # === Traffic spike alert ===
    if current_rate >= max(MIN_PACKETS_PER_WINDOW, TRAFFIC_SPIKE_MULTIPLIER * baseline_rate):
        insert_alert("N/A", "N/A", "ALL", "traffic_spike",
                     f"Traffic spike detected: {current_rate:.1f} packets/sec (baseline {baseline_rate:.1f})")
        # Reset baseline to reduce repeated alerts
        baseline_rate = current_rate / 2

    # Update baseline using simple exponential moving average
    alpha = 0.3
    baseline_rate = alpha * current_rate + (1 - alpha) * baseline_rate

    # === TCP detection ===
    if TCP in pkt:
        flags = pkt[TCP].flags
        insert_alert(src, dst, "TCP", "tcp_seen", f"Saw TCP packet with flags {flags}")

        # SYN scan detection
        if flags == "S":
            ports = syn_tracker[(src, dst)]
            ports.append((pkt[TCP].dport, now))
            while ports and ports[0][1] < now - WINDOW_SECONDS:
                ports.popleft()
            unique_ports = {p for p, _ in ports}
            if len(unique_ports) > MAX_PORTS:
                insert_alert(src, dst, "TCP", "portscan_detected",
                             f"Possible TCP port scan from {src} to {dst} on ports {list(unique_ports)}")
                ports.clear()

    # === UDP detection ===
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        insert_alert(src, dst, "UDP", "udp_seen",
                     f"Saw UDP packet {sport} -> {dport}")

        # UDP port scan detection
        ports = udp_tracker[(src, dst)]
        ports.append((dport, now))
        while ports and ports[0][1] < now - WINDOW_SECONDS:
            ports.popleft()
        unique_ports = {p for p, _ in ports}
        if len(unique_ports) > MAX_PORTS:
            insert_alert(src, dst, "UDP", "udp_portscan_detected",
                         f"Possible UDP port scan from {src} to {dst} on ports {list(unique_ports)}")
            ports.clear()


def start_sniffing():
    print("🔎 IDS is sniffing for TCP/UDP packets...")
    sniff(prn=handle_packet, store=0)


if __name__ == "__main__":
    start_sniffing()

