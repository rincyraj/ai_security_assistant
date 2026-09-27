def generate_security_summary(incident):
    summary = f"""
SECURITY INCIDENT

Incident Type: {incident['incident_type']}
Severity: {incident['severity']}
Risk Score: {incident['risk_score']}/100

User: {incident['user']}
Source IP: {incident['source_ip']}

Failed Login Attempts: {incident['failed_login_attempts']}
Follow-up Event: {incident['follow_up_event']}
Time Window: {incident['time_window_minutes']} minutes

Assessment:
Multiple failed login attempts were followed by a successful
IAM policy change involving the same user and source IP.

This activity may indicate a possible account compromise and
requires further investigation.
"""

    return summary


if __name__ == "__main__":
    test_incident = {
        "incident_type": "Possible Account Compromise",
        "severity": "CRITICAL",
        "risk_score": 85,
        "user": "admin",
        "source_ip": "185.23.45.91",
        "failed_login_attempts": 5,
        "follow_up_event": "IAMPolicyChange",
        "time_window_minutes": 10
    }

    print(generate_security_summary(test_incident))