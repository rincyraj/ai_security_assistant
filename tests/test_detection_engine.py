import sys

from sympy import python

sys.path.insert(0, "src")

from detection_engine import (
    detect_failed_logins,
    detect_suspicious_policy_change,
    detect_high_volume_s3_access,
    create_incidents,
    calculate_account_compromise_risk,
    calculate_data_access_risk,
)

def test_detect_failed_logins():
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
    ]


    alerts = detect_failed_logins(logs)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["type"] == "Brute Force Attack"
    assert alert["severity"] == "HIGH"
    assert alert["user"] == "admin"
    assert alert["source_ip"] == "185.23.45.91"
    assert alert["failed_attempts"] == 5
    assert alert["window_minutes"] == 5

def test_no_brute_force_alert_below_threshold():
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
    ]


    alerts = detect_failed_logins(logs)

    assert alerts == []

def test_brute_force_at_exact_five_minute_boundary():
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
    "timestamp": "2026-10-01T10:25:00",
    "event": "ConsoleLogin",
    "status": "Failed",
    "user": "admin",
    "source_ip": "185.23.45.91",
    },
    ]


    alerts = detect_failed_logins(logs)

    assert len(alerts) == 1
    assert alerts[0]["failed_attempts"] == 5
    assert alerts[0]["window_minutes"] == 5

from detection_engine import detect_suspicious_policy_change

def test_detect_suspicious_privilege_change():
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


    alerts = detect_suspicious_policy_change(logs)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["type"] == "Suspicious Privilege Change"
    assert alert["severity"] == "CRITICAL"
    assert alert["user"] == "admin"
    assert alert["source_ip"] == "185.23.45.91"
    assert alert["failed_logins"] == 5
    assert alert["event"] == "IAMPolicyChange"

def test_no_privilege_change_alert_outside_correlation_window():
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
    "timestamp": "2026-10-01T10:40:00",
    "event": "IAMPolicyChange",
    "status": "Success",
    "user": "admin",
    "source_ip": "185.23.45.91",
    },
    ]


    alerts = detect_suspicious_policy_change(logs)

    assert alerts == []

def test_detect_high_volume_s3_access():
    logs = [
    {
    "timestamp": "2026-10-01T11:00:00",
    "event": "S3ObjectAccess",
    "status": "Success",
    "user": "developer",
    "source_ip": "10.0.0.20",
    "resource": "s3://company-data/file1.csv",
    },
    {
    "timestamp": "2026-10-01T11:01:00",
    "event": "S3ObjectAccess",
    "status": "Success",
    "user": "developer",
    "source_ip": "10.0.0.20",
    "resource": "s3://company-data/file2.csv",
    },
    {
    "timestamp": "2026-10-01T11:02:00",
    "event": "S3ObjectAccess",
    "status": "Success",
    "user": "developer",
    "source_ip": "10.0.0.20",
    "resource": "s3://company-data/file3.csv",
    },
    {
    "timestamp": "2026-10-01T11:03:00",
    "event": "S3ObjectAccess",
    "status": "Success",
    "user": "developer",
    "source_ip": "10.0.0.20",
    "resource": "s3://company-data/file4.csv",
    },
    {
    "timestamp": "2026-10-01T11:04:00",
    "event": "S3ObjectAccess",
    "status": "Success",
    "user": "developer",
    "source_ip": "10.0.0.20",
    "resource": "s3://company-data/file5.csv",
    },
    ]


    alerts = detect_high_volume_s3_access(logs)

    assert len(alerts) == 1

    alert = alerts[0]

    assert alert["type"] == "High Volume S3 Access"
    assert alert["severity"] == "HIGH"
    assert alert["user"] == "developer"
    assert alert["source_ip"] == "10.0.0.20"
    assert alert["s3_accesses"] == 5
    assert alert["window_minutes"] == 5
    assert len(alert["resources"]) == 5

def test_no_high_volume_s3_alert_below_threshold():
    logs = [
    {
    "timestamp": "2026-10-01T11:00:00",
    "event": "S3ObjectAccess",
    "status": "Success",
    "user": "developer",
    "source_ip": "10.0.0.20",
    "resource": "s3://company-data/file1.csv",
    },
    {
    "timestamp": "2026-10-01T11:01:00",
    "event": "S3ObjectAccess",
    "status": "Success",
    "user": "developer",
    "source_ip": "10.0.0.20",
    "resource": "s3://company-data/file2.csv",
    },
    {
    "timestamp": "2026-10-01T11:02:00",
    "event": "S3ObjectAccess",
    "status": "Success",
    "user": "developer",
    "source_ip": "10.0.0.20",
    "resource": "s3://company-data/file3.csv",
    },
    {
    "timestamp": "2026-10-01T11:03:00",
    "event": "S3ObjectAccess",
    "status": "Success",
    "user": "developer",
    "source_ip": "10.0.0.20",
    "resource": "s3://company-data/file4.csv",
    },
    ]


    alerts = detect_high_volume_s3_access(logs)

    assert alerts == []

def test_create_incidents_from_alerts():
    alerts = [
        {
            "type": "Brute Force Attack",
            "severity": "HIGH",
            "user": "admin",
            "source_ip": "185.23.45.91",
            "failed_attempts": 5,
            "window_minutes": 5,
        },
        {
            "type": "Suspicious Privilege Change",
            "severity": "CRITICAL",
            "user": "admin",
            "source_ip": "185.23.45.91",
            "failed_logins": 5,
            "event": "IAMPolicyChange",
        },
        {
            "type": "High Volume S3 Access",
            "severity": "HIGH",
            "user": "developer",
            "source_ip": "10.0.0.20",
            "s3_accesses": 5,
            "resources": [
                "s3://company-data/file1.csv",
                "s3://company-data/file2.csv",
                "s3://company-data/file3.csv",
                "s3://company-data/file4.csv",
                "s3://company-data/file5.csv",
            ],
            "window_minutes": 5,
        },
    ]

    incidents = create_incidents(alerts)

    assert len(incidents) == 2

    assert incidents[0]["incident_type"] == (
        "Possible Account Compromise"
    )

    assert incidents[0]["risk_score"] == 85

    assert incidents[1]["incident_type"] == (
        "Possible Data Access Anomaly"
    )

    assert incidents[1]["risk_score"] == 40


def test_no_account_compromise_when_source_ip_differs():
    alerts = [
        {
            "type": "Brute Force Attack",
            "severity": "HIGH",
            "user": "admin",
            "source_ip": "185.23.45.91",
            "failed_attempts": 5,
            "window_minutes": 5,
        },
        {
            "type": "Suspicious Privilege Change",
            "severity": "CRITICAL",
            "user": "admin",
            "source_ip": "10.0.0.50",
            "failed_logins": 5,
            "event": "IAMPolicyChange",
        },
    ]

    incidents = create_incidents(alerts)

    assert incidents == []


def test_account_compromise_risk_score():
    brute_force = {
        "failed_attempts": 5,
        "user": "admin",
        "source_ip": "185.23.45.91",
    }

    privilege_change = {
        "event": "IAMPolicyChange",
        "source_ip": "185.23.45.91",
    }

    risk_score = calculate_account_compromise_risk(
        brute_force,
        privilege_change,
    )

    assert risk_score == 85


def test_data_access_risk_score():
    s3_access = {
        "s3_accesses": 5,
    }

    risk_score = calculate_data_access_risk(
        s3_access
    )

    assert risk_score == 40

