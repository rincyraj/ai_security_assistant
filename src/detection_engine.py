from datetime import datetime
from log_reader import load_logs

# Detect 5 failed login attempts from the same IP within 5 minutes.

def detect_failed_logins(logs, threshold=5, window_minutes=5):
    failed_logins = {}

    for log in logs:
        if log["event"] == "ConsoleLogin" and log["status"] == "Failed":
            key = (log["user"], log["source_ip"])

            timestamp = datetime.fromisoformat(log["timestamp"])

            if key not in failed_logins:
                failed_logins[key] = []

            failed_logins[key].append(timestamp)

    alerts = []

    for (user, source_ip), timestamps in failed_logins.items():

        timestamps.sort()

        for i in range(len(timestamps)):

            window_start = timestamps[i]

            attempts_in_window = [
                timestamp
                for timestamp in timestamps
                if 0 <= (timestamp - window_start).total_seconds()
                <= window_minutes * 60
            ]

            if len(attempts_in_window) >= threshold:
                alerts.append({
                    "type": "Brute Force Attack",
                    "severity": "HIGH",
                    "user": user,
                    "source_ip": source_ip,
                    "failed_attempts": len(attempts_in_window),
                    "window_minutes": window_minutes
                })

                break

    return alerts


if __name__ == "__main__":
    logs = load_logs()

    alerts = detect_failed_logins(logs)

    print(f"Alerts detected: {len(alerts)}")

    for alert in alerts:
        print(alert)