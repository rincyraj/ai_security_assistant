MITRE_TECHNIQUES = {
    "T1110": "Brute Force",
    "T1530": "Data from Cloud Storage",
    "T1078": "Valid Accounts",
    "T1059": "Command and Scripting Interpreter",
    "T1098": "Account Manipulation",
}


def validate_mitre_technique(technique_id, technique_name):
    """
    Validate whether a MITRE ATT&CK technique exists
    in the techniques supported by this application.
    """

    if technique_id not in MITRE_TECHNIQUES:
        return False, f"Unknown MITRE technique: {technique_id}"

    expected_name = MITRE_TECHNIQUES[technique_id]

    if technique_name.lower() != expected_name.lower():
        return False, (
            f"MITRE technique name mismatch: "
            f"{technique_id} should be '{expected_name}'"
        )

    return True, "Valid MITRE technique"


def validate_mitre_analysis(mitre_attack):
    """
    Validate all MITRE techniques returned by the AI.
    """

    if not isinstance(mitre_attack, list):
        raise ValueError("mitre_attack must be a list")

    for technique in mitre_attack:
        if not isinstance(technique, dict):
            raise ValueError("Each MITRE technique must be an object")

        technique_id = technique.get("technique_id")
        technique_name = technique.get("technique_name")

        if not technique_id or not technique_name:
            raise ValueError(
                "MITRE technique must contain technique_id and technique_name"
            )

        valid, message = validate_mitre_technique(
            technique_id,
            technique_name
        )

        if not valid:
            raise ValueError(message)

    return True

def validate_incident_mitre_mapping(incident, mitre_attack):
    """
    Validate that the MITRE technique returned by the AI
    matches the expected technique for the incident type.
    """

    expected_mappings = {
        "Possible Account Compromise": "T1110",
        "Possible Data Access Anomaly": "T1530",
    }

    incident_type = incident.get("incident_type")

    if incident_type not in expected_mappings:
        raise ValueError(
            f"No MITRE mapping defined for incident type: {incident_type}"
        )

    expected_technique_id = expected_mappings[incident_type]

    returned_technique_ids = [
        technique.get("technique_id")
        for technique in mitre_attack
    ]

    if expected_technique_id not in returned_technique_ids:
        raise ValueError(
            f"Incorrect MITRE mapping for '{incident_type}'. "
            f"Expected {expected_technique_id}, "
            f"but received {returned_technique_ids}"
        )

    return True