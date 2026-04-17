import streamlit as st
import os
from collections import Counter
from streamlit_autorefresh import st_autorefresh

LOG_FILE = "server.log"

st.set_page_config(
    page_title="ML IDS Dashboard",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ ML Intrusion Detection Dashboard")
st.markdown("Real-time monitoring with AI-based attack detection")

# ---------------- AUTO REFRESH ----------------
st_autorefresh(interval=2000, key="refresh")

# ---------------- SESSION STATE ----------------
if "seen_logs" not in st.session_state:
    st.session_state.seen_logs = set()

# ---------------- READ LOGS ----------------
def read_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        return f.readlines()[-100:]

logs = read_logs()

# ---------------- PROCESS LOGS ----------------
alerts = []
normal_logs = []
ips = []

for line in logs:
    line = line.strip()

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
    st.bar_chart(Counter(ips))
else:
    st.info("No data yet...")

st.divider()

# ---------------- DISPLAY ----------------
colA, colB = st.columns(2)

with colA:
    st.subheader("🚨 Alerts")
    if alerts:
        for a in alerts[-10:]:
            st.error(a)
    else:
        st.success("No alerts detected")

with colB:
    st.subheader("📜 Recent Logs")
    if normal_logs:
        for n in normal_logs[-10:]:
            st.text(n)
    else:
        st.info("No logs available")
