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
    validate_incident_mitre_mapping, MITRE_TECHNIQUES
)

def is_live_ai_enabled():
    """Enable Bedrock only when explicitly requested."""
    return os.getenv("AI_MODE", "demo").strip().lower() == "live"

def build_security_prompt(incident):
    incident_data = json.dumps(incident, indent=2)
    supported_mitre = json.dumps(
    MITRE_TECHNIQUES,
    indent=2
)

    prompt = f"""
    You are a cybersecurity incident analysis assistant.

    Analyze the following incident data.

    INCIDENT DATA:
    {incident_data}
    SUPPORTED MITRE ATT&CK TECHNIQUES:
    {supported_mitre}

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
    25. Use only technique IDs and names from the SUPPORTED MITRE ATT&CK TECHNIQUES catalogue.
    26. The technique name must match the catalogue entry for the selected ID.
    27. Map a technique only when the incident evidence supports it; do not invent missing events or actions.
    28. If the evidence is insufficient, return an empty "mitre_attack" array.
    29. Do not assume that a failed login proves valid credentials were used.
    30. Do not assume that an IAM policy change automatically establishes a specific MITRE technique.
        

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
    try:
        validate_mitre_analysis(
            analysis["mitre_attack"]
        )
    except (ValueError, TypeError) as exc:
        print(f"MITRE validation failed: {exc}")
        analysis["mitre_attack"] = []

   # Validate incident-specific MITRE mapping
    mitre_validation = validate_incident_mitre_mapping(
        incident,
        analysis["mitre_attack"]
    )

    # Only expose evidence-supported techniques to the UI
    analysis["mitre_attack"] = mitre_validation["accepted"]
    analysis["mitre_rejected"] = mitre_validation["rejected"]

    return True

SAMPLE_ANALYSES = {
    "Possible Account Compromise": {
        "summary": (
            "Five failed login attempts against the admin account "
            "were correlated with an IAM policy change from the same "
            "source IP within a 10-minute window. This is suspicious "
            "activity that requires investigation; account compromise "
            "has not been confirmed."
        ),
        "observed_evidence": [
            "Five failed login attempts were recorded for the admin account.",
            "The source IP associated with the incident is 185.23.45.91.",
            "An IAMPolicyChange follow-up event was correlated within a 10-minute window."
        ],
        "assessment": [
            "The combination of repeated failed logins and a subsequent IAM policy change warrants investigation.",
            "The available evidence does not establish whether a login succeeded or whether the policy change was unauthorized."
        ],
        "recommended_investigation": [
            "Review authentication logs around the failed login attempts to determine whether any subsequent login succeeded.",
            "Inspect the IAM policy change audit event to identify the affected policy, the principal that made the change, and whether the change was authorized."
        ],
        "recommended_remediation": [
            "If the policy change is confirmed to be unauthorized, revert it through the approved change process and review the affected permissions.",
            "If suspicious account access is confirmed, follow the organization's account containment and credential-reset procedures."
        ],
        "confidence": "medium",
        "mitre_attack": [
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "reason": "Five failed login attempts were recorded against the admin account."
            }
        ]
    },
    "Possible Data Access Anomaly": {
        "summary": (
            "The developer account accessed five S3 resources within "
            "a five-minute window. The resources include customer, "
            "employee, financial, application configuration, and "
            "internal data files. The available evidence does not "
            "establish whether the access was unauthorized."
        ),
        "observed_evidence": [
            "Five S3 resources were associated with the developer account within a five-minute window.",
            "The source IP recorded for this incident is 10.0.0.20.",
            "The listed resources include customer-data.csv, employee-data.csv, and financial-data.csv."
        ],
        "assessment": [
            "The concentration of access across multiple data resources may warrant review against the developer account's expected duties and access patterns.",
            "The available event data does not establish data exfiltration or unauthorized access."
        ],
        "recommended_investigation": [
            "Review S3 audit logs to confirm which operations were performed on each resource and whether they were authorized.",
            "Compare the access with the developer account's approved permissions, recent work, and normal access patterns."
        ],
        "recommended_remediation": [
            "If unauthorized access is confirmed, restrict the affected permissions using the approved access-management process.",
            "If the access violates data-handling requirements, follow the organization's incident-response and data-protection procedures."
        ],
       "confidence": "medium",
        "mitre_attack": [
    {
        "technique_id": "T1530",
        "technique_name": "Data from Cloud Storage",
        "reason": (
            "The incident involves access to multiple S3 data resources. "
            "This technique is a candidate for investigation; the available "
            "evidence does not establish unauthorized access."
        )
    }
]
    }
}

def run_security_analysis(logs=None):
    """
    Run the security detection pipeline.

    Demo mode: use saved analyses for default sample logs only.
    Live mode: generate and validate analysis using Bedrock.
    Uploaded logs in demo mode receive detection results only.
    """

    using_sample_logs = logs is None

    if using_sample_logs:
        logs = load_logs()

    # Step 1: Detect security alerts
    brute_force_alerts = detect_failed_logins(logs)

    policy_change_alerts = detect_suspicious_policy_change(logs)

    s3_access_alerts = detect_high_volume_s3_access(logs)

    alerts = (
        brute_force_alerts
        + policy_change_alerts
        + s3_access_alerts
    )

    # Step 2: Create correlated security incidents
    incidents = create_incidents(alerts)

    # Step 3: Generate analyses according to the selected mode
    analyses = []

    if is_live_ai_enabled():
        for incident in incidents:
            response = generate_security_analysis(incident)
            analysis = json.loads(response)

            validate_analysis(analysis, incident)

            analyses.append({
                "incident": incident,
                "analysis": analysis,
            })

    elif using_sample_logs:
        for incident in incidents:
            sample_analysis = SAMPLE_ANALYSES.get(
                incident["incident_type"]
            )

            if sample_analysis is not None:
                # Copy nested data so validation cannot alter the fixture.
                analysis = json.loads(json.dumps(sample_analysis))

                validate_analysis(analysis, incident)

                analyses.append({
                    "incident": incident,
                    "analysis": analysis,
                })

        print("Demo mode: Using saved sample incident analyses.")

    else:
        print(
            "Demo mode: Uploaded logs analyzed without live AI analysis."
        )

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

