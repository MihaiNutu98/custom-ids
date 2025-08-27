#!/usr/bin/env python3
import subprocess
import time
import sys
from ids.storage import init_db

# 1️⃣ Initialize DB
init_db()
print("✅ Database initialized.")

# 2️⃣ Start NIDS sniffer
sniffer = subprocess.Popen([sys.executable, "ids/sniff.py"])
print("🐍 Sniffer started...")

# 3️⃣ Start HIDS log monitor
hids = subprocess.Popen([sys.executable, "ids/hids.py"])
print("🛡️ HIDS started...")

time.sleep(2)  # Give IDS a moment to start

# 4️⃣ Trigger TCP SYN scan (requires sudo)
print("⚡ Triggering TCP SYN scan...")
subprocess.run(["sudo", "nmap", "-sS", "localhost"])

# 5️⃣ Trigger UDP scan (requires sudo)
print("⚡ Triggering UDP scan...")
subprocess.run(["sudo", "nmap", "-sU", "-p", "53,67,68,69", "localhost"])

# 6️⃣ Trigger SSH brute-force (demo only)
print("⚡ Triggering SSH brute-force on demo_user (3 failed attempts)...")
for _ in range(3):
    subprocess.run(
        ["ssh", "demo_user@localhost"],
        input=b"wrongpassword\n",
        check=False
    )

# 7️⃣ Trigger traffic spike (HTTP server + ab)
print("⚡ Triggering HTTP traffic spike...")
http_server = subprocess.Popen([sys.executable, "-m", "http.server", "8080"])
time.sleep(2)
subprocess.run(["ab", "-n", "1000", "-c", "50", "http://127.0.0.1:8080/"])
http_server.terminate()

print("✅ Demo attacks complete! Launching dashboard...")

# 8️⃣ Launch Streamlit dashboard headless
print("🌐 Streamlit dashboard running at http://localhost:8501")
subprocess.run([
    sys.executable, "-m", "streamlit", "run", "ids/app_streamlit.py",
    "--server.headless=true",
    "--browser.serverAddress=localhost",
    "--server.port=8501"
])

# Optional: leave sniffer & HIDS running or terminate
# sniffer.terminate()
# hids.terminate()

