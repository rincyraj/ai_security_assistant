from datetime import datetime
from log_reader import load_logs

#2 Detect 5 failed login attempts from the same IP within 5 minutes.
#3 event correlation.Detect 5 failed login attempts and became successful after policy change(10:20 → Failed login,10:21 → Failed login,
# 10:22 → Failed login,10:23 → Failed login,10:24 → Failed login
# 10:30 → IAMPolicyChange → Success)

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

def detect_suspicious_policy_change(logs, failed_login_threshold=5):
    alerts = []

    failed_logins = {}

    # Step 1: Find failed login attempts
    for log in logs:
        if log["event"] == "ConsoleLogin" and log["status"] == "Failed":
            key = (log["user"], log["source_ip"])

            timestamp = datetime.fromisoformat(log["timestamp"])

            if key not in failed_logins:
                failed_logins[key] = []

            failed_logins[key].append(timestamp)

    # Step 2: Look for IAM policy changes
    for log in logs:
        if log["event"] == "IAMPolicyChange" and log["status"] == "Success":

            policy_user = log["user"]
            policy_timestamp = datetime.fromisoformat(log["timestamp"])

            # Step 3: Check whether this user had multiple failed logins
            for (user, source_ip), timestamps in failed_logins.items():

                if user != policy_user:
                    continue

                recent_failures = [
                    timestamp
                    for timestamp in timestamps
                    if 0 <= (policy_timestamp - timestamp).total_seconds()
                    <= 10 * 60
                ]

                if len(recent_failures) >= failed_login_threshold:
                    alerts.append({
                        "type": "Suspicious Privilege Change",
                        "severity": "CRITICAL",
                        "user": user,
                        "source_ip": source_ip,
                        "failed_logins": len(recent_failures),
                        "event": "IAMPolicyChange"
                    })

    return alerts

def create_incidents(alerts):
    incidents = []

    brute_force_alerts = [
        alert for alert in alerts
        if alert["type"] == "Brute Force Attack"
    ]

    privilege_change_alerts = [
        alert for alert in alerts
        if alert["type"] == "Suspicious Privilege Change"
    ]

    for brute_force in brute_force_alerts:

        for privilege_change in privilege_change_alerts:

            if (
                brute_force["user"] == privilege_change["user"]
                and brute_force["source_ip"] == privilege_change["source_ip"]
            ):
                risk_score = 90

                incident = {
                    "incident_type": "Possible Account Compromise",
                    "severity": "CRITICAL",
                    "risk_score": risk_score,
                    "user": brute_force["user"],
                    "source_ip": brute_force["source_ip"],
                    "failed_login_attempts": brute_force["failed_attempts"],
                    "follow_up_event": privilege_change["event"],
                    "time_window_minutes": 10
                }

                incidents.append(incident)

    return incidents

if __name__ == "__main__":
    logs = load_logs()

    brute_force_alerts = detect_failed_logins(logs)

    policy_change_alerts = detect_suspicious_policy_change(logs)

    alerts = brute_force_alerts + policy_change_alerts

    print(f"Alerts detected: {len(alerts)}")

    for alert in alerts:
        print(alert)

    incidents = create_incidents(alerts)

    print("\nIncidents detected:", len(incidents))

    for incident in incidents:
        print(incident)