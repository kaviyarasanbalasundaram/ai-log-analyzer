import streamlit as st
import pandas as pd
from detector import detect_threats
from ai_model import detect_anomalies
import re
from collections import Counter

# Load logs
with open("logs.txt") as f:
    logs = f.readlines()

# Process data
alerts = detect_threats(logs)
anomalies = detect_anomalies(logs)

# Title
st.title("AI-Powered Log Analyzer (Mini SIEM)")

# =========================
# 📊 SOC SUMMARY
# =========================
st.subheader("📊 SOC Summary")

col1, col2 = st.columns(2)

col1.metric("Total Logs", len(logs))
col2.metric("Total Alerts", len(alerts))

# =========================
# 🚨 ALERTS
# =========================
st.subheader("🚨 Security Alerts")

for alert in alerts:
    st.write(f"Severity: {alert[0]} | Score: {alert[1]} | Log: {alert[2]}")

# =========================
# 🤖 AI ANOMALY DETECTION
# =========================
st.subheader("🤖 AI Anomaly Detection")

st.write(anomalies)

# =========================
# 📈 ALERT GRAPH
# =========================
st.subheader("📈 Alert Distribution")

if alerts:
    df = pd.DataFrame(alerts, columns=["Severity", "Score", "Log"])
    st.bar_chart(df["Severity"].value_counts())

# =========================
# 🌍 TOP ATTACKER IP
# =========================
def extract_ip(log):
    match = re.search(r'\d+\.\d+\.\d+\.\d+', log)
    return match.group() if match else None

ips = [extract_ip(log) for log in logs if extract_ip(log)]
top_ip = Counter(ips).most_common(1)

if top_ip:
    st.subheader("🌍 Top Attacker IP")
    st.write(f"IP: {top_ip[0][0]} | Attempts: {top_ip[0][1]}")

# =========================
# 🔍 SEARCH LOGS
# =========================
st.subheader("🔍 Search Logs")

search = st.text_input("Enter keyword")

for log in logs:
    if search and search.lower() in log.lower():
        st.write(log)

# =========================
# 📁 EXPORT ALERTS
# =========================
st.subheader("📁 Export Alerts")

if alerts:
    df = pd.DataFrame(alerts, columns=["Severity", "Score", "Log"])

    st.download_button(
        label="Download Alerts CSV",
        data=df.to_csv(index=False),
        file_name="alerts.csv",
        mime="text/csv"
    )