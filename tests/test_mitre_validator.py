import sys

from sympy import python

sys.path.insert(0, "src")


from mitre_validator import (
    validate_mitre_technique,
    validate_incident_mitre_mapping,
)



def test_valid_mitre_technique():
    valid, message = validate_mitre_technique(
        "T1110",
        "Brute Force",
    )

    assert valid is True
    assert message == "Valid MITRE technique"


def test_unknown_mitre_technique():
    valid, message = validate_mitre_technique(
        "T9999",
        "Unknown Technique",
    )

    assert valid is False
    assert message == "Unknown MITRE technique: T9999"


def test_mitre_technique_name_mismatch():
    valid, message = validate_mitre_technique(
        "T1110",
        "Account Manipulation",
    )

    assert valid is False
    assert message == (
        "MITRE technique name mismatch: "
        "T1110 should be 'Brute Force'"
    )



def test_unsupported_mitre_technique_is_rejected():
    incident = {
        "incident_type": "Possible Account Compromise",
    }

    mitre_attack = [
        {
            "technique_id": "T1098",
            "technique_name": "Account Manipulation",
            "reason": (
                "The IAM policy change may indicate "
                "account manipulation."
            ),
        }
    ]

    result = validate_incident_mitre_mapping(
        incident,
        mitre_attack,
    )

    assert result["accepted"] == []

    assert len(result["rejected"]) == 1

    assert result["rejected"][0]["technique_id"] == "T1098"


def test_empty_mitre_mapping_is_rejected():
    incident = {
        "incident_type": "Possible Account Compromise",
    }

    mitre_attack = []

    try:
        validate_incident_mitre_mapping(
            incident,
            mitre_attack,
        )
        assert False, (
            "Expected ValueError for empty MITRE mapping"
        )
    except ValueError as error:
        assert (
            "No evidence-supported MITRE technique"
            in str(error)
        )


def test_supported_and_unsupported_mitre_techniques():
    incident = {
        "incident_type": "Possible Account Compromise",
    }

    mitre_attack = [
        {
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "reason": (
                "Five failed login attempts were "
                "observed for the same user and source IP."
            ),
        },
        {
            "technique_id": "T1098",
            "technique_name": "Account Manipulation",
            "reason": (
                "The IAM policy change may indicate "
                "account manipulation."
            ),
        },
    ]

    result = validate_incident_mitre_mapping(
        incident,
        mitre_attack,
    )

    assert len(result["accepted"]) == 1
    assert (
        result["accepted"][0]["technique_id"]
        == "T1110"
    )

    assert len(result["rejected"]) == 1
    assert (
        result["rejected"][0]["technique_id"]
        == "T1098"
    )

