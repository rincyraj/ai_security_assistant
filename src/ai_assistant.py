from llm_client import LLMClient
import json


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

IMPORTANT RULES

1. Only use facts explicitly provided in the incident data.
2. Do not invent events, IP reputation, successful logins, attacker identity, or other evidence.
3. Clearly distinguish observed evidence from your security assessment.
4. Recommendations should be investigation steps, not claims that an attack definitely occurred.
5. Return ONLY valid JSON.
6. Do not use Markdown.
7. Do not include ```json or any other code fences.
8. Only map a MITRE ATT&CK technique when the observed evidence directly supports the technique.
9. Do not map a technique based only on speculation or on what an event could potentially mean.
10. Do not map Account Manipulation (T1098) for an IAMPolicyChange event unless the incident data explicitly shows account or permission manipulation that matches the technique.
11. If there is insufficient evidence for a MITRE ATT&CK technique, do not include it.
12. If no MITRE ATT&CK technique is sufficiently supported, return an empty list.

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
  "confidence": "low|medium|high",
  mitre_attack": [
  {{"technique_id": "T1110",
      "technique_name": "Brute Force",
      "reason": "Five failed login attempts were observed against the admin account."
    }}
    
]
}}
"""
    return prompt


def generate_security_analysis(incident):
    prompt = build_security_prompt(incident)

    llm = LLMClient()

    response = llm.generate(prompt)

    return response

def validate_analysis(analysis):
    required_fields = {
        "summary": str,
        "observed_evidence": list,
        "assessment": list,
        "recommended_investigation": list,
        "confidence": str,
        "mitre_attack": list,
    }

    for field, expected_type in required_fields.items():
        if field not in analysis:
            raise ValueError(f"Missing required field: {field}")

        if not isinstance(analysis[field], expected_type):
            raise ValueError(
                f"Field '{field}' must be {expected_type.__name__}"
            )

    if analysis["confidence"] not in {"low", "medium", "high"}:
        raise ValueError(
            "confidence must be one of: low, medium, high"
        )

    return True

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

    response = generate_security_analysis(test_incident)
    analysis = json.loads(response)
    validate_analysis(analysis)

    print("AI analysis validation: PASSED")
    print(json.dumps(analysis, indent=2))

    # print(analysis)
    # print(analysis["summary"])
    # print(analysis["observed_evidence"])
    # print(analysis["recommended_investigation"])        