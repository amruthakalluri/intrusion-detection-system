import time
import re
from collections import defaultdict
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

LOG_FILE = "server.log"

# ---------------- ML MODEL ----------------
data = pd.read_csv("data.csv")

X = data[["duration", "failed_logins", "requests"]]
y = data["label"]

model = RandomForestClassifier()
model.fit(X, y)

print("ML Model Loaded...")

# ---------------- TRACKING ----------------
failed_attempts = defaultdict(int)
request_count = defaultdict(list)
start_time = defaultdict(lambda: time.time())

TIME_WINDOW = 10  # seconds


def ml_detect(ip):
    duration = int(time.time() - start_time[ip])
    failed = failed_attempts[ip]
    requests = len(request_count[ip])

    sample = [[duration, failed, requests]]
    result = model.predict(sample)[0]

    return result


def process_line(line):
    ip_match = re.search(r'IP=(\d+\.\d+\.\d+\.\d+)', line)
    status_match = re.search(r'STATUS=(\w+)', line)

    if not ip_match:
        return

    ip = ip_match.group(1)
    status = status_match.group(1) if status_match else "UNKNOWN"

    current_time = time.time()

    # Track failed attempts
    if status == "FAILED":
        failed_attempts[ip] += 1

    # Track requests
    request_count[ip].append(current_time)
    request_count[ip] = [
        t for t in request_count[ip]
        if current_time - t <= TIME_WINDOW
    ]

    # ML Detection
    result = ml_detect(ip)

    if result == "Attack":
        print(f" ML ALERT: Intrusion detected from {ip}")


class LogHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_position = 0

    def on_modified(self, event):
        if event.src_path.endswith(LOG_FILE):
            with open(LOG_FILE, "r") as file:
                file.seek(self.last_position)
                new_lines = file.readlines()
                self.last_position = file.tell()

                for line in new_lines:
                    process_line(line.strip())


if __name__ == "__main__":
    print("ML Intrusion Detection System Running...")

    event_handler = LogHandler()
    observer = Observer()
    observer.schedule(event_handler, path=".", recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()