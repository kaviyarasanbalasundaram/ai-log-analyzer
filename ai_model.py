from sklearn.ensemble import IsolationForest
import pandas as pd

def detect_anomalies(logs):
    # Convert logs into numeric feature (length of log)
    data = [len(log) for log in logs]

    df = pd.DataFrame(data, columns=["log_length"])

    # Train model
    model = IsolationForest(contamination=0.3)
    df["anomaly"] = model.fit_predict(df)

    return df