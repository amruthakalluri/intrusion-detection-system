import streamlit as st
import time
import os
from collections import Counter

LOG_FILE = "server.log"

st.set_page_config(page_title="ML IDS Dashboard", page_icon="🛡️", layout="wide")

st.title("🛡️ ML Intrusion Detection Dashboard")
st.markdown("Real-time monitoring with AI-based attack detection")

# ---------------- SESSION STATE ----------------
if "seen_logs" not in st.session_state:
    st.session_state.seen_logs = set()

# ---------------- READ LOGS ----------------
def read_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        return f.readlines()[-100:]

# ---------------- MAIN LOOP ----------------
# ---------------- MAIN LOOP ----------------

logs = read_logs()

new_logs = []

for line in logs:
    line = line.strip()
    if line not in st.session_state.seen_logs:
        new_logs.append(line)
        st.session_state.seen_logs.add(line)

alerts = []
normal_logs = []
ips = []

for line in new_logs:
    if "IP=" in line:
        ip = line.split("IP=")[-1].split()[0]
        ips.append(ip)

    if "ALERT" in line or "FAILED" in line:
        alerts.append(line)
    else:
        normal_logs.append(line)

    # ---------------- METRICS ----------------
    col1, col2, col3 = st.columns(3)

    col1.metric("🚨 Alerts", len(alerts))
    col2.metric("✅ Normal Logs", len(normal_logs))
    col3.metric("🌐 Unique IPs", len(set(ips)))

    st.divider()

    # ---------------- CHART ----------------
    st.subheader("📊 Top Attacker IPs")

    if ips:
        ip_counts = Counter(ips)
        st.bar_chart(ip_counts)
    else:
        st.write("No data yet...")

    st.divider()

    # ---------------- ALERTS ----------------
    colA, colB = st.columns(2)

    with colA:
        st.subheader("🚨 Alerts")
        for a in alerts[-10:]:
            st.error(a)

    with colB:
        st.subheader("📜 Recent Logs")
        for n in normal_logs[-10:]:
            st.text(n)

   
