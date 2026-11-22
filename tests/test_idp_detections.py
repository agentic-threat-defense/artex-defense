"""Tests for native Okta & Microsoft Entra ID parsers and IdP 2FA/spray/SP detections."""

import json
from pathlib import Path

from artex_defense.detectors import scan_telemetry_file
from artex_defense.parsers import parse_auto


def _write_jsonl(path: Path, records: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
    return path


def test_native_okta_and_entra_parsers_extract_idp_fields(tmp_path: Path) -> None:
    okta_rec = {
        "published": "2026-11-21T10:00:01.000Z",
        "eventType": "user.mfa.okta_verify.deny_push",
        "actor": {"alternateId": "sbarnes@corp.local"},
        "client": {"ipAddress": "203.0.113.245", "userAgent": {"rawUserAgent": "Mozilla/5.0 Chrome/131.0"}},
        "outcome": {"result": "FAILURE", "reason": "VERIFICATION_ERROR"},
        "debugContext": {"debugData": {"requestUri": "/api/v1/authn/factors/verify"}},
        "target": [{"displayName": "Okta Verify"}],
    }
    entra_rec = {
        "createdDateTime": "2026-11-21T10:00:05.000Z",
        "ipAddress": "198.51.100.249",
        "servicePrincipalName": "sp-connectwise-backup",
        "resourceDisplayName": "Azure Key Vault",
        "isInteractive": False,
        "status": {"errorCode": 7000215, "failureReason": "Invalid client secret"},
    }
    events = parse_auto(_write_jsonl(tmp_path / "idp_mix.jsonl", [okta_rec, entra_rec]))
    assert len(events) == 2
    assert events[0]["appliance"] == "okta"
    assert events[0]["source_host"] == "203.0.113.245"
    assert events[0]["actor"] == "sbarnes@corp.local"
    assert events[0]["status_code"] == 401
    assert "deny_push" in events[0]["action"]

    assert events[1]["appliance"] == "entra_id"
    assert events[1]["event_type"] == "idp_sp_auth"
    assert events[1]["dest_host"] == "Azure Key Vault"
    assert "err_7000215" in events[1]["action"]


def test_benign_single_mfa_typo_and_password_retry_produce_zero_fps(tmp_path: Path) -> None:
    """One normal user mistyping an OTP once + retrying cleanly must NOT trigger MFA fatigue."""
    records = [
        {
            "published": "2026-11-21T11:00:01.000Z",
            "eventType": "user.authentication.auth_via_mfa",
            "actor": {"alternateId": "jdoe@corp.local"},
            "client": {"ipAddress": "198.51.100.40", "userAgent": {"rawUserAgent": "Mozilla/5.0 Chrome/131.0"}},
            "outcome": {"result": "FAILURE", "reason": "VERIFICATION_ERROR"},
            "debugContext": {"debugData": {"requestUri": "/login/step-up"}},
            "target": [{"displayName": "Okta Verify"}],
        },
        {
            "published": "2026-11-21T11:00:12.000Z",
            "eventType": "user.authentication.auth_via_mfa",
            "actor": {"alternateId": "jdoe@corp.local"},
            "client": {"ipAddress": "198.51.100.40", "userAgent": {"rawUserAgent": "Mozilla/5.0 Chrome/131.0"}},
            "outcome": {"result": "SUCCESS", "reason": ""},
            "debugContext": {"debugData": {"requestUri": "/login/step-up"}},
            "target": [{"displayName": "Okta Verify"}],
        },
    ]
    assert scan_telemetry_file(_write_jsonl(tmp_path / "benign_mfa_typo.jsonl", records)) == []


def test_entra_mfa_fatigue_500121_and_security_info_registration_caught(tmp_path: Path) -> None:
    """Entra ID 500121 MFA denial burst + immediate Register security info must trigger alert tier."""
    records = [
        {
            "createdDateTime": f"2026-11-21T12:00:{i * 4:02d}.000Z",
            "ipAddress": "203.0.113.199",
            "userPrincipalName": "exec@corp.local",
            "resourceDisplayName": "Office 365",
            "isInteractive": True,
            "status": {"errorCode": 500121, "failureReason": "Authentication failed during strong authentication request"},
        }
        for i in range(4)
    ] + [
        {
            "activityDateTime": "2026-11-21T12:00:30.000Z",
            "ipAddress": "203.0.113.199",
            "userPrincipalName": "exec@corp.local",
            "operationName": "Register security info",
            "result": "success",
        }
    ]
    cands = scan_telemetry_file(_write_jsonl(tmp_path / "entra_mfa_attack.jsonl", records))
    assert cands and "idp_mfa_fatigue_or_2fa_tampering" in cands[0].reasons
    assert cands[0].alert_tier == "alert" and cands[0].risk_score >= 90


def test_okta_mass_probe_account_registration_and_workflow_abuse_caught(tmp_path: Path) -> None:
    """Okta Threat Intel Oct/Nov 2026: mass self-service probe signups + Workflows invoke/clientToken abuse."""
    reg_records = [
        {
            "published": f"2026-11-21T13:00:{i * 3:02d}.000Z",
            "eventType": "user.lifecycle.create",
            "actor": {"alternateId": f"probe_acct_{i}@throwaway.example"},
            "client": {"ipAddress": "203.0.113.210", "userAgent": {"rawUserAgent": "Mozilla/5.0 Chrome/131.0"}},
            "outcome": {"result": "SUCCESS", "reason": ""},
            "debugContext": {"debugData": {"requestUri": "/api/v1/users"}},
        }
        for i in range(6)
    ]
    cands_reg = scan_telemetry_file(_write_jsonl(tmp_path / "okta_probe_reg.jsonl", reg_records))
    assert any("idp_probe_registration_or_workflow_abuse" in c.reasons for c in cands_reg)

    wf_records = [
        {
            "published": "2026-11-21T13:05:01.000Z",
            "eventType": "workflows.user.invoke",
            "actor": {"alternateId": "probe_acct_0@throwaway.example"},
            "client": {"ipAddress": "203.0.113.211", "userAgent": {"rawUserAgent": "python-httpx/0.27"}},
            "outcome": {"result": "SUCCESS", "reason": ""},
            "debugContext": {"debugData": {"requestUri": "/api/flo/abc123/invoke?clientToken=leak"}},
        }
    ]
    cands_wf = scan_telemetry_file(_write_jsonl(tmp_path / "okta_workflow_abuse.jsonl", wf_records))
    assert cands_wf and "idp_probe_registration_or_workflow_abuse" in cands_wf[0].reasons
    assert cands_wf[0].alert_tier == "alert"

    # Benign control: single normal user signup must produce 0 FPs
    benign_signup = [reg_records[0]]
    assert scan_telemetry_file(_write_jsonl(tmp_path / "benign_single_signup.jsonl", benign_signup)) == []


def test_duo_pingfederate_and_google_workspace_parsers_and_2fa_detections(tmp_path: Path) -> None:
    """Verify native Duo Security, PingFederate, and Google Workspace parsers, attack detections, and 0 benign FPs."""
    # 1. Duo Security: user explicitly reports fraud on push bombing + benign Duo success control
    duo_attack = [
        {
            "isotimestamp": "2026-11-21T14:00:01Z",
            "txid": "duo-tx-1001",
            "user": {"name": "cfo@corp.local"},
            "access_device": {"ip": "203.0.113.140", "browser": "Chrome"},
            "application": {"name": "Corporate VPN"},
            "factor": "duo_push",
            "result": "fraud",
            "reason": "fraud_reported",
        }
    ]
    duo_parsed = parse_auto(_write_jsonl(tmp_path / "duo_fraud.jsonl", duo_attack))
    assert duo_parsed[0]["appliance"] == "duo"
    c_duo = scan_telemetry_file(tmp_path / "duo_fraud.jsonl")
    assert c_duo and "idp_mfa_fatigue_or_2fa_tampering" in c_duo[0].reasons
    assert c_duo[0].alert_tier == "alert" and c_duo[0].risk_score >= 90

    duo_benign = [
        {
            "isotimestamp": "2026-11-21T14:01:00Z",
            "txid": "duo-tx-1002",
            "user": {"name": "jdoe@corp.local"},
            "access_device": {"ip": "198.51.100.20", "browser": "Chrome"},
            "application": {"name": "Corporate VPN"},
            "factor": "duo_push",
            "result": "success",
            "reason": "user_approved",
        }
    ]
    assert scan_telemetry_file(_write_jsonl(tmp_path / "duo_benign.jsonl", duo_benign)) == []

    # 2. PingFederate: 5-account spray followed by SSO success + benign single SSO control
    pf_attack = [
        {
            "timestamp": f"2026-11-21T14:05:{i * 3:02d}Z",
            "trackingid": f"tid-pf-{i}",
            "adapterid": "HTMLFormAdapter",
            "event": "AUTHN_ATTEMPT",
            "ip": "203.0.113.141",
            "subject": f"emp{i}@corp.local",
            "app": "FinancePortal",
            "status": "failure",
            "description": "Invalid credentials",
        }
        for i in range(5)
    ] + [
        {
            "timestamp": "2026-11-21T14:05:25Z",
            "trackingid": "tid-pf-succ",
            "adapterid": "HTMLFormAdapter",
            "event": "SSO",
            "ip": "203.0.113.141",
            "subject": "emp4@corp.local",
            "app": "FinancePortal",
            "status": "success",
            "description": "SSO completed",
        }
    ]
    pf_parsed = parse_auto(_write_jsonl(tmp_path / "pf_spray.jsonl", pf_attack))
    assert pf_parsed[0]["appliance"] == "pingfederate"
    c_pf = scan_telemetry_file(tmp_path / "pf_spray.jsonl")
    assert any("idp_spray_then_success" in c.reasons for c in c_pf)

    assert scan_telemetry_file(_write_jsonl(tmp_path / "pf_benign.jsonl", [pf_attack[-1]])) == []

    # 3. Google Workspace Reports API: 2SV disabled + recovery phone edited -> alert, benign login -> 0 FP
    gws_attack = [
        {
            "kind": "admin#reports#activity",
            "id": {"time": "2026-11-21T14:10:00Z", "applicationName": "login"},
            "actor": {"email": "vp@corp.local"},
            "ipAddress": "203.0.113.142",
            "events": [{"type": "account_warning", "name": "2sv_disable", "parameters": []}],
        },
        {
            "kind": "admin#reports#activity",
            "id": {"time": "2026-11-21T14:10:08Z", "applicationName": "login"},
            "actor": {"email": "vp@corp.local"},
            "ipAddress": "203.0.113.142",
            "events": [{"type": "account_warning", "name": "recovery_phone_edit", "parameters": []}],
        },
    ]
    gws_parsed = parse_auto(_write_jsonl(tmp_path / "gws_tamper.jsonl", gws_attack))
    assert gws_parsed[0]["appliance"] == "google_workspace"
    c_gws = scan_telemetry_file(tmp_path / "gws_tamper.jsonl")
    assert c_gws and "idp_mfa_fatigue_or_2fa_tampering" in c_gws[0].reasons
    assert c_gws[0].alert_tier == "alert"

    gws_benign = [
        {
            "kind": "admin#reports#activity",
            "id": {"time": "2026-11-21T14:15:00Z", "applicationName": "login"},
            "actor": {"email": "alice@corp.local"},
            "ipAddress": "198.51.100.25",
            "events": [{"type": "login", "name": "login_success", "parameters": [{"name": "is_suspicious", "boolValue": False}]}],
        }
    ]
    assert scan_telemetry_file(_write_jsonl(tmp_path / "gws_benign.jsonl", gws_benign)) == []


def test_federated_cross_rp_trust_probe_caught_with_zero_monday_morning_sso_fps(tmp_path: Path) -> None:
    """Verify tight idp_federated_trust_probe catches multi-client_id OAuth errors & fresh-signup fan-out with 0 SSO FPs."""
    # Attack A: Single actor probing 4 distinct OAuth client_ids with 400/403 authorization errors
    multi_err = [
        {
            "timestamp": f"2026-11-21T15:00:{i * 4:02d}Z",
            "source_host": "203.0.113.175",
            "actor": "probe-fed-user@throwaway.example",
            "event_type": "idp_auth",
            "surface": "cloud_iam",
            "dest_host": f"rp-{i}.example",
            "http_method": "GET",
            "http_path": f"/oauth2/authorize?client_id=app_client_{i}&scope=openid+admin&acr_values=ial1",
            "user_agent": "Mozilla/5.0 Chrome/131.0",
            "status_code": 403,
            "action": "unauthorized_client",
        }
        for i in range(4)
    ]
    c_err = scan_telemetry_file(_write_jsonl(tmp_path / "fed_multi_err.jsonl", multi_err))
    assert any("idp_federated_trust_probe" in c.reasons for c in c_err)

    # Attack B: Newly self-registered federated account immediately hitting 3 distinct Relying Parties in same session
    fresh_pivot = [
        {
            "timestamp": "2026-11-21T15:05:00Z",
            "source_host": "203.0.113.176",
            "actor": "brandnew99@throwaway.example",
            "event_type": "idp_auth",
            "surface": "cloud_iam",
            "dest_host": "broker.example",
            "http_method": "POST",
            "http_path": "/oauth/register",
            "user_agent": "Mozilla/5.0 Chrome/131.0",
            "status_code": 200,
            "action": "user.lifecycle.create",
        }
    ] + [
        {
            "timestamp": f"2026-11-21T15:05:{10 + i * 5:02d}Z",
            "source_host": "203.0.113.176",
            "actor": "brandnew99@throwaway.example",
            "event_type": "idp_auth",
            "surface": "cloud_iam",
            "dest_host": f"portal-{i}.example",
            "http_method": "GET",
            "http_path": f"/oidc/authorize?client_id=portal_{i}&prompt=none",
            "user_agent": "Mozilla/5.0 Chrome/131.0",
            "status_code": 200,
            "action": "sso_handshake",
        }
        for i in range(3)
    ]
    c_fresh = scan_telemetry_file(_write_jsonl(tmp_path / "fed_fresh_pivot.jsonl", fresh_pivot))
    assert any("idp_federated_trust_probe" in c.reasons for c in c_fresh)

    # Hard Benign Control 1: Existing employee Monday-morning 6-app SSO burst (all 200 OK in 10s) -> MUST be 0 FPs!
    monday_sso = [
        {
            "timestamp": f"2026-11-21T09:00:{i * 2:02d}Z",
            "source_host": "198.51.100.60",
            "actor": "employee@corp.local",
            "event_type": "idp_auth",
            "surface": "cloud_iam",
            "dest_host": f"{app}.corp.local",
            "http_method": "GET",
            "http_path": f"/oauth2/authorize?client_id={app}_prod",
            "user_agent": "Mozilla/5.0 Chrome/131.0",
            "status_code": 200,
            "action": "sso_success",
        }
        for i, app in enumerate(["mail", "slack", "jira", "github", "workday", "confluence"])
    ]
    assert scan_telemetry_file(_write_jsonl(tmp_path / "benign_monday_sso.jsonl", monday_sso)) == []

    # Hard Benign Control 2: Existing employee with 1 broken bookmark (403) + 4 normal 200 OK apps -> MUST be 0 FPs!
    one_broken = [{**monday_sso[0], "status_code": 403, "action": "access_denied"}] + monday_sso[1:5]
    assert scan_telemetry_file(_write_jsonl(tmp_path / "benign_one_broken_sso.jsonl", one_broken)) == []


def test_idp_oauth_redirect_uri_wildcard_dns_evasion(tmp_path: Path) -> None:
    """Detect OAuth redirect_uri pointing to wildcard IP-reflecting DNS (including URL-encoded) without benign FP."""
    evil_oauth = [
        {
            "timestamp": "2026-11-22T17:45:00Z",
            "source_host": "198.51.100.71",
            "actor": "attacker@external.example",
            "surface": "cloud_iam",
            "event_type": "idp_auth",
            "dest_host": "corp.okta.com",
            "http_path": "/oauth2/v1/authorize?client_id=0oa123&redirect_uri=https%3A%2F%2F45-33-32-156.sslip.io%2Fcb",
            "status_code": 400,
            "action": "invalid_redirect_uri",
        }
    ]
    cands = scan_telemetry_file(_write_jsonl(tmp_path / "oauth_sslip.jsonl", evil_oauth))
    assert cands and any("idp_probe_registration_or_workflow_abuse" in c.reasons for c in cands)

    # Benign local dev OAuth using localtest.me or normal corp redirect_uri must NOT trigger OAuth or SSRF alerts
    benign_oauth = [
        {
            "timestamp": "2026-11-22T17:46:00Z",
            "source_host": "10.0.5.20",
            "actor": "dev@corp.local",
            "surface": "cloud_iam",
            "event_type": "idp_auth",
            "dest_host": "corp.okta.com",
            "http_path": "/oauth2/v1/authorize?client_id=dev_app&redirect_uri=https%3A%2F%2Fapp.corp.local%2Fcallback",
            "status_code": 200,
            "action": "sso_success",
        },
        {
            "timestamp": "2026-11-22T17:46:05Z",
            "source_host": "10.0.5.20",
            "actor": "dev@corp.local",
            "surface": "cloud_iam",
            "event_type": "idp_auth",
            "dest_host": "corp.okta.com",
            "http_path": "/oauth2/v1/authorize?client_id=dev_app&redirect_uri=http%3A%2F%2Flocaltest.me%3A3000%2Fcallback",
            "status_code": 200,
            "action": "sso_success",
        },
    ]
    assert scan_telemetry_file(_write_jsonl(tmp_path / "oauth_benign.jsonl", benign_oauth)) == []
