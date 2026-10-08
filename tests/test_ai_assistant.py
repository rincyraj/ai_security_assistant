import sys
import pytest
from sympy import python

sys.path.insert(0, "src")

from ai_assistant import validate_analysis
from ai_assistant import run_security_analysis


def test_validate_analysis_success():
    incident = {
        "incident_type": "Possible Account Compromise",
    }

    analysis = {
        "summary": (
            "Five failed login attempts were observed "
            "for the admin user from the same source IP."
        ),
        "observed_evidence": [
            "Five failed ConsoleLogin attempts were observed."
        ],
        "assessment": [
            "The activity is consistent with a brute-force pattern."
        ],
        "recommended_investigation": [
            "Review authentication activity for the affected user."
        ],
        "recommended_remediation": [
            "If unauthorized activity is confirmed, "
            "reset the affected credentials."
        ],
        "confidence": "high",
        "mitre_attack": [
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "reason": (
                    "Five failed login attempts support "
                    "the Brute Force technique."
                ),
            }
        ],
    }

    result = validate_analysis(
        analysis,
        incident,
    )

    assert result is True




def test_validate_analysis_missing_required_field():
    incident = {
        "incident_type": "Possible Account Compromise",
    }

    analysis = {
        "observed_evidence": [
            "Five failed ConsoleLogin attempts were observed."
        ],
        "assessment": [
            "The activity is consistent with a brute-force pattern."
        ],
        "recommended_investigation": [
            "Review authentication activity for the affected user."
        ],
        "recommended_remediation": [
            "If unauthorized activity is confirmed, "
            "reset the affected credentials."
        ],
        "confidence": "high",
        "mitre_attack": [
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "reason": (
                    "Five failed login attempts support "
                    "the Brute Force technique."
                ),
            }
        ],
    }

    with pytest.raises(
        ValueError,
        match="Missing required field: summary",
    ):
        validate_analysis(
            analysis,
            incident,
        )


def test_validate_analysis_invalid_confidence():
    incident = {
        "incident_type": "Possible Account Compromise",
    }

    analysis = {
        "summary": (
            "Five failed login attempts were observed "
            "for the admin user from the same source IP."
        ),
        "observed_evidence": [
            "Five failed ConsoleLogin attempts were observed."
        ],
        "assessment": [
            "The activity is consistent with a brute-force pattern."
        ],
        "recommended_investigation": [
            "Review authentication activity for the affected user."
        ],
        "recommended_remediation": [
            "If unauthorized activity is confirmed, "
            "reset the affected credentials."
        ],
        "confidence": "very_high",
        "mitre_attack": [
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "reason": (
                    "Five failed login attempts support "
                    "the Brute Force technique."
                ),
            }
        ],
    }

    with pytest.raises(
        ValueError,
        match="confidence must be one of",
    ):
        validate_analysis(
            analysis,
            incident,
        )


def test_validate_analysis_rejects_bullet_only_recommendation():
    incident = {
        "incident_type": "Possible Account Compromise",
    }

    analysis = {
        "summary": (
            "Five failed login attempts were observed "
            "for the admin user from the same source IP."
        ),
        "observed_evidence": [
            "Five failed ConsoleLogin attempts were observed."
        ],
        "assessment": [
            "The activity is consistent with a brute-force pattern."
        ],
        "recommended_investigation": [
            "-"
        ],
        "recommended_remediation": [
            "If unauthorized activity is confirmed, "
            "reset the affected credentials."
        ],
        "confidence": "high",
        "mitre_attack": [
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "reason": (
                    "Five failed login attempts support "
                    "the Brute Force technique."
                ),
            }
        ],
    }

    with pytest.raises(
        ValueError,
        match="contains invalid",
    ):
        validate_analysis(
            analysis,
            incident,
        )


#empty recommendation
def test_validate_analysis_rejects_empty_recommendation():
    incident = {
        "incident_type": "Possible Account Compromise",
    }

    analysis = {
        "summary": (
            "Five failed login attempts were observed "
            "for the admin user from the same source IP."
        ),
        "observed_evidence": [
            "Five failed ConsoleLogin attempts were observed."
        ],
        "assessment": [
            "The activity is consistent with a brute-force pattern."
        ],
        "recommended_investigation": [
            ""
        ],
        "recommended_remediation": [
            "If unauthorized activity is confirmed, "
            "reset the affected credentials."
        ],
        "confidence": "high",
        "mitre_attack": [
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "reason": (
                    "Five failed login attempts support "
                    "the Brute Force technique."
                ),
            }
        ],
    }

    with pytest.raises(
        ValueError,
        match="contains invalid",
    ):
        validate_analysis(
            analysis,
            incident,
        )


def test_full_security_analysis_pipeline(monkeypatch):
    logs = [
        {
            "timestamp": "2026-10-01T10:20:00",
            "event": "ConsoleLogin",
            "status": "Failed",
            "user": "admin",
            "source_ip": "185.23.45.91",
        },
        {
            "timestamp": "2026-10-01T10:21:00",
            "event": "ConsoleLogin",
            "status": "Failed",
            "user": "admin",
            "source_ip": "185.23.45.91",
        },
        {
            "timestamp": "2026-10-01T10:22:00",
            "event": "ConsoleLogin",
            "status": "Failed",
            "user": "admin",
            "source_ip": "185.23.45.91",
        },
        {
            "timestamp": "2026-10-01T10:23:00",
            "event": "ConsoleLogin",
            "status": "Failed",
            "user": "admin",
            "source_ip": "185.23.45.91",
        },
        {
            "timestamp": "2026-10-01T10:24:00",
            "event": "ConsoleLogin",
            "status": "Failed",
            "user": "admin",
            "source_ip": "185.23.45.91",
        },
        {
            "timestamp": "2026-10-01T10:30:00",
            "event": "IAMPolicyChange",
            "status": "Success",
            "user": "admin",
            "source_ip": "185.23.45.91",
        },
    ]

    mocked_response = """
    {
        "summary": "Five failed login attempts were observed for the admin user.",
        "observed_evidence": [
            "Five failed ConsoleLogin attempts were observed."
        ],
        "assessment": [
            "The activity is consistent with a brute-force pattern."
        ],
        "recommended_investigation": [
            "Review authentication activity for the affected user."
        ],
        "recommended_remediation": [
            "If unauthorized activity is confirmed, reset the affected credentials."
        ],
        "confidence": "high",
        "mitre_attack": [
            {
                "technique_id": "T1110",
                "technique_name": "Brute Force",
                "reason": "Five failed login attempts support the Brute Force technique."
            }
        ]
    }
    """

    monkeypatch.setattr(
        "ai_assistant.generate_security_analysis",
        lambda incident: mocked_response,
    )

    results = run_security_analysis(logs)

    assert len(results["alerts"]) == 2
    assert len(results["incidents"]) == 1
    assert len(results["analyses"]) == 1

    assert (
        results["incidents"][0]["incident_type"]
        == "Possible Account Compromise"
    )

    assert (
        results["analyses"][0]["analysis"]["confidence"]
        == "high"
    )

    assert (
        results["analyses"][0]["analysis"]["mitre_attack"][0][
            "technique_id"
        ]
        == "T1110"
    )

