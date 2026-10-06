import json

from llm_client import LLMClient
from log_reader import load_logs
from detection_engine import (
    detect_failed_logins,
    detect_suspicious_policy_change,
    detect_high_volume_s3_access,
    create_incidents,
)


def build_security_prompt(incident):
    incident_data = json.dumps(incident, indent=2)

    prompt = f"""
You are a cybersecurity incident analysis assistant.

Analyze the following incident data.

INCIDENT DATA:
{incident_data}

Your task is to provide a structured security analysis based ONLY on the information explicitly present in the incident data.

Return ONLY valid JSON using exactly this structure:

{{
  "summary": "Brief summary of the incident based only on the provided evidence.",
  "observed_evidence": [
    "Facts directly observed in the incident data."
  ],
  "assessment": [
    "Security interpretation of the observed evidence."
  ],
  "recommended_investigation": [
    "Investigation steps that would help determine whether the activity is legitimate or unauthorized."
  ],
  "recommended_remediation": [
    "Conditional remediation actions based on investigation findings."
  ],
  "confidence": "low",
  "mitre_attack": [
    {{
      "technique_id": "TXXXX",
      "technique_name": "Technique name",
      "reason": "Reason the observed evidence directly supports this technique."
    }}
  ]
}}

IMPORTANT RULES:

1. Only use facts explicitly provided in the incident data.
2. Do not invent events, IP reputation, successful logins, attacker identity, or other evidence.
3. Clearly distinguish observed evidence from security assessment.
4. Recommended investigation steps must investigate the incident; do not claim that an attack or compromise definitely occurred.
5. Return ONLY valid JSON.
6. Do not use Markdown.
7. Do not use code fences.
8. Only map a MITRE ATT&CK technique when the observed incident evidence directly supports it.
9. Do not map a MITRE technique based only on speculation or what an event could potentially mean.
10. Do not map Account Manipulation (T1098) for IAMPolicyChange unless the incident data explicitly shows account or permission manipulation matching that technique.
11. If there is insufficient evidence for a MITRE ATT&CK technique, do not include it.
12. If no MITRE ATT&CK technique is sufficiently supported, return an empty list.
13. Remediation recommendations must be conditional on investigation findings and must not assume compromise or unauthorized activity has been confirmed.
14. Do not recommend incident-specific remediation based on controls or configurations that are not present in the incident data. General security improvements are allowed.
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
        "recommended_remediation": list,
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
    logs = load_logs()

    brute_force_alerts = detect_failed_logins(logs)

    policy_change_alerts = detect_suspicious_policy_change(logs)
    s3_access_alerts = detect_high_volume_s3_access(logs)

    alerts = brute_force_alerts + policy_change_alerts+ s3_access_alerts

    incidents = create_incidents(alerts)

    print(f"Alerts detected: {len(alerts)}")
    print(f"Incidents detected: {len(incidents)}")

    for incident in incidents:
        print("\nAnalyzing incident:")
        print(json.dumps(incident, indent=2))

        response = generate_security_analysis(incident)

        analysis = json.loads(response)

        validate_analysis(analysis)

        print("\nAI analysis validation: PASSED")
        print(json.dumps(analysis, indent=2))