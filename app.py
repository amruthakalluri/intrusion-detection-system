import streamlit as st
import time
import os

LOG_FILE = "server.log"

st.set_page_config(page_title="ML IDS", page_icon="🛡️")

st.title("ML Intrusion Detection System")
st.write("Real-time monitoring with AI detection")

placeholder = st.empty()


def read_logs():
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, "r") as f:
        return f.readlines()[-30:]


for _ in range(1000):
    logs = read_logs()

    normal_logs = []
    alerts = []

    for line in logs:
        if "FAILED" in line:
            alerts.append(f"{line}")
        else:
            normal_logs.append(line)

    placeholder.empty()

    st.subheader("Alerts")
    for a in alerts:
        st.error(a)

    st.subheader("Normal Logs")
    for n in normal_logs:
        st.text(n)

    time.sleep(2)