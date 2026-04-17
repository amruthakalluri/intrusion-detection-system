import streamlit as st
import time
import os

LOG_FILE = "server.log"

st.set_page_config(page_title="ML IDS", page_icon="🛡️")

st.title("ML Intrusion Detection System")
st.write("Real-time monitoring with AI detection")

# ---------------- SESSION STATE ----------------
if "seen_logs" not in st.session_state:
    st.session_state.seen_logs = set()

# ---------------- READ LOGS ----------------
def read_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        return f.readlines()[-50:]  # last 50 logs

# ---------------- MAIN LOOP ----------------
while True:
    logs = read_logs()

    new_logs = []

    for line in logs:
        line = line.strip()
        if line not in st.session_state.seen_logs:
            new_logs.append(line)
            st.session_state.seen_logs.add(line)

    alerts = []
    normal_logs = []

    for line in new_logs:
        if "ALERT" in line or "FAILED" in line:
            alerts.append(line)
        else:
            normal_logs.append(line)

    # ---------------- UI ----------------
    st.subheader("Alerts")
    for a in alerts:
        st.error(a)

    st.subheader("✅ Normal Logs")
    for n in normal_logs:
        st.text(n)

    time.sleep(2)
    st.rerun()
