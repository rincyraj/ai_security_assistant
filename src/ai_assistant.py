from llm_client import LLMClient


def build_security_prompt(incident):
    prompt = f"""
You are a cybersecurity analyst assisting with security incident investigation.

Analyze the following security incident.

INCIDENT DATA

Incident Type: {incident['incident_type']}
Severity: {incident['severity']}
Risk Score: {incident['risk_score']}/100

User: {incident['user']}
Source IP: {incident['source_ip']}

Failed Login Attempts: {incident['failed_login_attempts']}
Follow-up Event: {incident['follow_up_event']}
Time Window: {incident['time_window_minutes']} minutes

IMPORTANT RULES

1. Only use facts explicitly provided in the incident data.
2. Do not invent events, IP reputation, successful logins, attacker identity, or other evidence.
3. Clearly distinguish observed evidence from your security assessment.
4. Recommendations should be investigation steps, not claims that an attack definitely occurred.
5. Return ONLY valid JSON.
6. Do not use Markdown.
7. Do not include ```json or any other code fences.

Return exactly this JSON structure:

{{
  "summary": "Short explanation of what happened",
  "observed_evidence": [
    "Evidence directly present in the incident data"
  ],
  "assessment": [
    "Security interpretation based on the evidence"
  ],
  "recommended_investigation": [
    "Investigation step"
  ],
  "confidence": "low|medium|high"
}}
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