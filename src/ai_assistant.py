import json
import os

from llm_client import LLMClient
from log_reader import load_logs
from detection_engine import (
    detect_failed_logins,
    detect_suspicious_policy_change,
    detect_high_volume_s3_access,
    create_incidents,
)
from mitre_validator import (
    validate_mitre_analysis,
    validate_incident_mitre_mapping,
)


def build_security_prompt(incident):
    incident_data = json.dumps(incident, indent=2)

    prompt = f"""
You are a cybersecurity incident analysis assistant.

Analyze the following incident data.

INCIDENT DATA:
{incident_data}

Your task is to provide a structured security analysis based ONLY on
the information explicitly present in the incident data.

Return ONLY valid JSON.

Use exactly this structure:

{{
  "summary": "Brief summary of the incident based only on the provided evidence.",
  "observed_evidence": [
    "Complete sentence describing one directly observed fact."
  ],
  "assessment": [
    "Complete sentence describing one security interpretation."
  ],
  "recommended_investigation": [
    "Complete sentence describing one investigation step."
  ],
  "recommended_remediation": [
    "Complete sentence describing one conditional remediation action."
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

IMPORTANT OUTPUT RULES:

1. Return ONLY valid JSON.
2. Do not use Markdown.
3. Do not use code fences.
4. Do not use bullet points.
5. Do not put "-", "*", "•", or other bullet characters as array items.
6. Every item in every array must be a complete, meaningful sentence.
7. Do not return empty strings.
8. Each recommendation must contain an actual investigation or remediation action.
9. Do not repeat the same recommendation.
10. If there are no valid items for an optional array, return [].
11. Only use facts explicitly provided in the incident data.
12. Do not invent events, IP reputation, successful logins, attacker identity, or other evidence.
13. Clearly distinguish observed evidence from security assessment.
14. Recommended investigation steps must investigate the incident; do not claim that an attack or compromise definitely occurred.
15. Recommended remediation actions must be conditional on investigation findings.
16. Do not assume that compromise or unauthorized activity has been confirmed.
17. Do not recommend incident-specific remediation based on controls or configurations that are not present in the incident data.
18. General security improvements are allowed.
19. Only map a MITRE ATT&CK technique when the observed incident evidence directly supports it.
20. Do not map a MITRE technique based only on speculation.
21. Do not map Account Manipulation (T1098) for IAMPolicyChange unless the incident data explicitly shows account or permission manipulation matching that technique.
22. If there is insufficient evidence for a MITRE ATT&CK technique, do not include it.
23. If no MITRE ATT&CK technique is sufficiently supported, return an empty list.
24. Confidence must be exactly one of: "low", "medium", "high".

Before returning the JSON, verify that every array item is a
non-empty complete sentence and does not contain only "-", "*", or "•".
"""

    return prompt


def generate_security_analysis(incident):
    prompt = build_security_prompt(incident)

    llm = LLMClient(
        profile_name=os.getenv("AWS_PROFILE")
    )

    response = llm.generate(prompt)

    return response


def validate_non_empty_string_list(
    field_name,
    values,
):
    if not isinstance(values, list):
        raise ValueError(
            f"Field '{field_name}' must be a list"
        )

    invalid_items = []

    for item in values:

        if not isinstance(item, str):
            invalid_items.append(item)
            continue

        cleaned = item.strip()

        if not cleaned:
            invalid_items.append(item)
            continue

        if cleaned in {"-", "*", "•"}:
            invalid_items.append(item)
            continue

    if invalid_items:
        raise ValueError(
            f"Field '{field_name}' contains invalid "
            f"empty or bullet-only items: {invalid_items}"
        )


def validate_analysis(analysis, incident):
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
            raise ValueError(
                f"Missing required field: {field}"
            )

        if not isinstance(
            analysis[field],
            expected_type,
        ):
            raise ValueError(
                f"Field '{field}' must be "
                f"{expected_type.__name__}"
            )

    # Validate text arrays
    validate_non_empty_string_list(
        "observed_evidence",
        analysis["observed_evidence"],
    )

    validate_non_empty_string_list(
        "assessment",
        analysis["assessment"],
    )

    validate_non_empty_string_list(
        "recommended_investigation",
        analysis["recommended_investigation"],
    )

    validate_non_empty_string_list(
        "recommended_remediation",
        analysis["recommended_remediation"],
    )

    # Validate confidence
    if analysis["confidence"] not in {
        "low",
        "medium",
        "high",
    }:
        raise ValueError(
            "confidence must be one of: low, medium, high"
        )

    # Validate MITRE ATT&CK analysis
    validate_mitre_analysis(
        analysis["mitre_attack"]
    )

    # Validate incident-specific MITRE mapping
    validate_incident_mitre_mapping(
        incident,
        analysis["mitre_attack"]
    )

    return True


def run_security_analysis(logs=None):
    """
    Run the complete security analysis pipeline.

    Returns:
        dict containing alerts, incidents, and AI analyses.
    """

    if logs is None:
        logs = load_logs()

    # Step 1: Detect security alerts
    brute_force_alerts = detect_failed_logins(logs)

    policy_change_alerts = detect_suspicious_policy_change(
        logs
    )

    s3_access_alerts = detect_high_volume_s3_access(
        logs
    )

    alerts = (
        brute_force_alerts
        + policy_change_alerts
        + s3_access_alerts
    )

    # Step 2: Create correlated security incidents
    incidents = create_incidents(alerts)

    # Step 3: Generate and validate AI analysis
    analyses = []

    for incident in incidents:

        response = generate_security_analysis(
            incident
        )

        analysis = json.loads(response)

        validate_analysis(
            analysis,
            incident,
        )

        analyses.append({
            "incident": incident,
            "analysis": analysis,
        })

    return {
        "alerts": alerts,
        "incidents": incidents,
        "analyses": analyses,
    }


if __name__ == "__main__":

    results = run_security_analysis()

    print("Pipeline test PASSED")
    print("Alerts:", len(results["alerts"]))
    print("Incidents:", len(results["incidents"]))
    print(
        "AI analyses:",
        len(results["analyses"]),
    )

