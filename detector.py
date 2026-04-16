import re
from collections import Counter

# -------------------------------
# 🔹 Extract IP Address
# -------------------------------
def extract_ip(log):
    match = re.search(r'\d+\.\d+\.\d+\.\d+', log)
    return match.group() if match else None


# -------------------------------
# 🔹 Threat Scoring Function
# -------------------------------
def calculate_threat_score(log):
    score = 0
    log_lower = log.lower()

    if "failed login" in log_lower:
        score += 5

    if "sql injection" in log_lower:
        score += 10

    return score


# -------------------------------
# 🔹 Main Detection Function
# -------------------------------
def detect_threats(logs):
    alerts = []
    ip_list = []

    for log in logs:
        log_lower = log.lower()
        score = calculate_threat_score(log)

        # Collect IPs for correlation
        if "failed login" in log_lower:
            ip = extract_ip(log)
            if ip:
                ip_list.append(ip)

        # Normal alert generation
        if score > 0:
            severity = "Low"

            if score >= 10:
                severity = "High"
            elif score >= 5:
                severity = "Medium"

            alerts.append((severity, score, log.strip()))

    # -------------------------------
    # 🔥 Event Correlation (Advanced)
    # -------------------------------
    count = Counter(ip_list)

    for ip, c in count.items():
        if c >= 3:
            alerts.append(("High", 15, f"Brute Force Attack from IP: {ip} (Attempts: {c})"))

    return alerts
