import re
import time
from collections import defaultdict
from storage import init_db, insert_alert

LOG_FILE = "/var/log/auth.log"  # Ubuntu/Debian
FAIL_THRESHOLD = 5              # failures to trigger alert
WINDOW_SECONDS = 120            # time window in seconds

init_db()

# track failed login attempts: {ip: [(timestamp1), (timestamp2), ...]}
fail_tracker = defaultdict(list)

def tail_f(file):
    file.seek(0,2)  # go to EOF
    while True:
        line = file.readline()
        if not line:
            time.sleep(0.5)
            continue
        yield line

def monitor():
    with open(LOG_FILE, "r") as f:
        for line in tail_f(f):
            match = re.search(r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                src = match.group(1)
                now = time.time()
                fail_tracker[src].append(now)
                # remove old timestamps
                fail_tracker[src] = [t for t in fail_tracker[src] if t > now - WINDOW_SECONDS]
                if len(fail_tracker[src]) >= FAIL_THRESHOLD:
                    insert_alert(src, None, "SSH", "ssh_bruteforce_confirmed",
                                 f"{len(fail_tracker[src])} failed logins in {WINDOW_SECONDS}s")
                    print(f"[ALERT] SSH brute-force detected from {src}")
                    fail_tracker[src] = []  # reset after alert

if __name__ == "__main__":
    monitor()

