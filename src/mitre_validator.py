MITRE_TECHNIQUES = {
    "T1110": "Brute Force",
    "T1530": "Data from Cloud Storage",
    "T1078": "Valid Accounts",
    "T1059": "Command and Scripting Interpreter",
    "T1098": "Account Manipulation",
    "T1484": "Domain or Tenant Policy Modification",
}


# Evidence-supported MITRE mappings for the
# detection rules currently implemented.
#
# This is the security control layer.
# The LLM may suggest techniques, but these mappings
# determine which techniques are accepted.

INCIDENT_MITRE_MAPPINGS = {
    "Possible Account Compromise": {
        "T1110",
    },
    "Possible Data Access Anomaly": {
        "T1530",
    },
}


def validate_mitre_technique(
    technique_id,
    technique_name,
):
    """
    Validate that the technique exists in the application's
    known MITRE technique catalogue and that its name matches.
    """

    if technique_id not in MITRE_TECHNIQUES:
        return False, (
            f"Unknown MITRE technique: {technique_id}"
        )

    expected_name = MITRE_TECHNIQUES[
        technique_id
    ]

    if technique_name.lower() != expected_name.lower():
        return False, (
            f"MITRE technique name mismatch: "
            f"{technique_id} should be "
            f"'{expected_name}'"
        )

    return True, "Valid MITRE technique"


def validate_mitre_analysis(mitre_attack):
    """
    Validate the structure and identity of techniques
    returned by the LLM.
    """

    if not isinstance(mitre_attack, list):
        raise ValueError(
            "mitre_attack must be a list"
        )

    for technique in mitre_attack:

        if not isinstance(technique, dict):
            raise ValueError(
                "Each MITRE technique must be an object"
            )

        technique_id = technique.get(
            "technique_id"
        )

        technique_name = technique.get(
            "technique_name"
        )

        reason = technique.get(
            "reason"
        )

        if not technique_id or not technique_name:
            raise ValueError(
                "MITRE technique must contain "
                "technique_id and technique_name"
            )

        if not reason or not isinstance(reason, str):
            raise ValueError(
                "MITRE technique must contain "
                "a meaningful reason"
            )

        valid, message = validate_mitre_technique(
            technique_id,
            technique_name,
        )

        if not valid:
            raise ValueError(message)

    return True


def validate_incident_mitre_mapping(
    incident,
    mitre_attack,
):
    """
    Validate MITRE mappings against the incident type.

    Supported techniques are retained.

    Unsupported techniques are rejected and returned
    separately so the application can display a
    validation warning rather than crashing.
    """

    incident_type = incident.get(
        "incident_type"
    )

    if incident_type not in INCIDENT_MITRE_MAPPINGS:
        raise ValueError(
            f"No MITRE mapping defined for incident type: "
            f"{incident_type}"
        )

    allowed_ids = INCIDENT_MITRE_MAPPINGS[
        incident_type
    ]

    accepted_techniques = []
    rejected_techniques = []

    for technique in mitre_attack:

        technique_id = technique.get(
            "technique_id"
        )

        if technique_id in allowed_ids:

            accepted_techniques.append(
                technique
            )

        else:

            rejected_techniques.append({
                "technique_id": technique_id,
                "technique_name": technique.get(
                    "technique_name",
                    "Unknown",
                ),
                "reason": (
                    "The AI suggested this technique, "
                    "but the available incident evidence "
                    "does not support it."
                ),
            })

    if not accepted_techniques and not rejected_techniques:
        raise ValueError(
            f"No evidence-supported MITRE technique "
            f"was returned for '{incident_type}'. "
            f"Expected one of: "
            f"{sorted(allowed_ids)}"
        )
    return {
        "accepted": accepted_techniques,
        "rejected": rejected_techniques,
    }

