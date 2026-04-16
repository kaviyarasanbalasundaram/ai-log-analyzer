from detector import detect_threats
from ai_model import detect_anomalies

with open("logs.txt") as f:
    logs = f.readlines()

# Rule-based alerts
alerts = detect_threats(logs)

# AI-based detection
anomalies = detect_anomalies(logs)

print("=== ALERTS ===")
for alert in alerts:
    print(alert)

print("\n=== AI ANOMALY DETECTION ===")
print(anomalies)