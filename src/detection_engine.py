from log_reader import load_logs

#5 failed login attempts from the same IP within 5 minutes.

def detect_failed_logins(logs, threshold=5):
    failed_logins = {}

    for log in logs:
        if log["event"] == "ConsoleLogin" and log["status"] == "Failed":
            key = (log["user"], log["source_ip"])

            failed_logins[key] = failed_logins.get(key, 0) + 1

    alerts = []

    for (user, source_ip), count in failed_logins.items():
        if count >= threshold:
            alerts.append({
                "type": "Brute Force Attack",
                "severity": "HIGH",
                "user": user,
                "source_ip": source_ip,
                "failed_attempts": count
            })

    return alerts


if __name__ == "__main__":
    logs = load_logs()

    alerts = detect_failed_logins(logs)

    print(f"Alerts detected: {len(alerts)}")

    for alert in alerts:
        print(alert)