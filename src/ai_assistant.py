from llm_client import LLMClient


def build_security_prompt(incident):
    prompt = f"""
You are a cybersecurity analyst assisting with security incident investigation.

Analyze the following security incident.

Incident Type: {incident['incident_type']}
Severity: {incident['severity']}
Risk Score: {incident['risk_score']}/100

User: {incident['user']}
Source IP: {incident['source_ip']}

Failed Login Attempts: {incident['failed_login_attempts']}
Follow-up Event: {incident['follow_up_event']}
Time Window: {incident['time_window_minutes']} minutes

Explain:

1. What happened?
2. Why is this activity suspicious?
3. What evidence supports the assessment?
4. What should a security analyst investigate next?

Do not invent information that is not present in the incident.
"""

    return prompt


def generate_security_analysis(incident):
    prompt = build_security_prompt(incident)

    llm = LLMClient()

    response = llm.generate(prompt)

    return response


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

    analysis = generate_security_analysis(test_incident)

    print(analysis)