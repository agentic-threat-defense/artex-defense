"""Automated multi-backend pySigma compilation and BushidoToken self-proclaimed UA regression tests."""

import json
from pathlib import Path

from artex_defense.detectors import scan_telemetry_file
from artex_defense.eval_harness import evaluate_sigma_rule_on_events
from artex_defense.sigma_compiler import compile_sigma_directory
import yaml

RULES_DIR = Path(__file__).resolve().parent.parent / "rules" / "sigma"


def test_all_sigma_rules_compile_across_enterprise_siem_backends(tmp_path: Path) -> None:
    report = compile_sigma_directory(RULES_DIR, export_dir=tmp_path)

    assert report["total_rules"] >= 13
    assert report["schema_issues"] == [], f"pySigma schema issues: {report['schema_issues']}"
    assert report["all_ok"] is True, f"Sigma compilation failures: {report['targets']}"

    by_key = {t["key"]: t for t in report["targets"]}

    # Full-pack compilation targets (all 13 rules)
    for full_key in ("esql_ecs", "lucene_ecs", "kusto_generic", "crowdstrike_logscale", "splunk_spl"):
        t = by_key[full_key]
        assert t["applicable"] == report["total_rules"]
        assert t["compiled"] == report["total_rules"], f"{full_key} failures: {t['failures']}"
        assert t["failed"] == 0
        assert t["exported_file"] is not None and Path(t["exported_file"]).stat().st_size > 200
        # Guard against backends returning a raw str being iterated char-by-char
        for item in t["rules"]:
            assert len(item["query"].splitlines()) < 30, f"{full_key}/{item['file']} query looks malformed"

    # Strict Windows endpoint schema targets (>=6 Windows process/network rules)
    for ep_key in ("kusto_mde_xdr", "kusto_sentinel_asim", "sentinelone_s1ql"):
        t = by_key[ep_key]
        assert t["applicable"] >= 6
        assert t["compiled"] == t["applicable"], f"{ep_key} failures: {t['failures']}"
        assert t["failed"] == 0
        assert t["exported_file"] is not None and Path(t["exported_file"]).stat().st_size > 100


def test_bushidotoken_self_proclaimed_authorized_uas_detected_by_engine_and_sigma(tmp_path: Path) -> None:
    events = [
        {
            "timestamp": "2026-11-20T20:00:01.000Z",
            "source_host": "198.51.100.210",
            "actor": "198.51.100.210",
            "event_type": "http",
            "surface": "web_portal",
            "http_method": "GET",
            "http_path": "/api/v1/status",
            "user_agent": "LLMLeak-RedTeam/1.0 (authorised-scan)",
            "status_code": 200,
        },
        {
            "timestamp": "2026-11-20T20:00:15.000Z",
            "source_host": "198.51.100.211",
            "actor": "198.51.100.211",
            "event_type": "http",
            "surface": "web_portal",
            "http_method": "GET",
            "http_path": "/.well-known/security.txt",
            "user_agent": "authorized-security-research/1.0 (+vulnerability-disclosure-policy-review)",
            "status_code": 200,
        },
        {
            "timestamp": "2026-11-20T20:00:30.000Z",
            "source_host": "198.51.100.212",
            "actor": "198.51.100.212",
            "event_type": "http",
            "surface": "web_portal",
            "http_method": "GET",
            "http_path": "/robots.txt",
            "user_agent": "authorized-exposure-audit/6",
            "status_code": 200,
        },
    ]
    log_path = tmp_path / "bushidotoken_uas.jsonl"
    log_path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")

    candidates = scan_telemetry_file(log_path)
    assert len(candidates) == 3, f"Expected all 3 BushidoToken UAs flagged individually: {candidates}"
    for cand in candidates:
        assert "agentic_user_agent_burst" in cand.reasons

    rule_doc = yaml.safe_load((RULES_DIR / "artex_unit42_canary_and_spec_targeting.yml").read_text(encoding="utf-8"))
    assert evaluate_sigma_rule_on_events(rule_doc, events) == 3


def test_compiled_siem_packs_pass_real_wire_schema_and_syntax_linter(tmp_path: Path) -> None:
    """Seat 4 regression guard: catch double-quoted KQL fields, quoted int ports,
    uppercase ES|QL .caseless literals, bad S1QL numeric operators, and broken DNS Computer mappings."""
    import re

    report = compile_sigma_directory(RULES_DIR, export_dir=tmp_path)
    assert report["all_ok"] is True
    by_key = {t["key"]: t for t in report["targets"]}

    # 1. KQL packs: no double-quoted identifiers, no single-quoted string-literal field names,
    #    and no quoted string ports on integer columns
    for kql_key in ("kusto_generic", "kusto_mde_xdr", "kusto_sentinel_asim"):
        text = Path(by_key[kql_key]["exported_file"]).read_text(encoding="utf-8")
        assert "''c-uri''" not in text, f"{kql_key} emitted double-quoted field"
        assert "''" not in text, f"{kql_key} emitted double-quoted identifier"
        assert 'in~ ("8787"' not in text, f"{kql_key} emitted quoted string ports on integer column"
        assert 'in~ ("7000215"' not in text, f"{kql_key} emitted quoted string Entra errorCode"
        assert "=~ true" not in text and "=~ false" not in text, f"{kql_key} used string operator =~ on bool"
        if kql_key in ("kusto_mde_xdr", "kusto_sentinel_asim"):
            assert "in (8787, 8788, 8790, 8890)" in text, f"{kql_key} missing unquoted integer port list"

    # 2. Elastic ES|QL pack: every *.caseless like/in literal must be all-lowercase,
    #    and DNS ComputerName must map to ECS winlog.computer_name/host.name (never winlog.event_data.Computer)
    esql_text = Path(by_key["esql_ecs"]["exported_file"]).read_text(encoding="utf-8")
    assert "winlog.event_data.Computer" not in esql_text
    assert "winlog.computer_name" in esql_text or "host.name" in esql_text
    for match in re.finditer(r'\b[\w.]+\.caseless\s+like\s+"([^"]+)"', esql_text):
        lit = match.group(1)
        assert lit == lit.lower(), f"ES|QL .caseless literal contains uppercase chars: {lit!r}"
    for match in re.finditer(r"\b[\w.]+\.caseless\s+in\s*\(([^)]+)\)", esql_text):
        lit_list = match.group(1)
        assert lit_list == lit_list.lower(), f"ES|QL .caseless in(...) contains uppercase chars: {lit_list!r}"

    # 3. SentinelOne S1QL: numeric port list must use exact `In`, never `In Contains AnyCase`
    s1_text = Path(by_key["sentinelone_s1ql"]["exported_file"]).read_text(encoding="utf-8")
    assert "In Contains AnyCase (8787" not in s1_text
    assert "DstPort In (8787,8788,8790,8890)" in s1_text

    # 4. Splunk SPL: web/proxy fields mapped to CIM (uri_path, http_user_agent, status, dest)
    spl_text = Path(by_key["splunk_spl"]["exported_file"]).read_text(encoding="utf-8")
    assert '"c-uri"' not in spl_text
    assert "uri_path IN " in spl_text or "uri_path=" in spl_text


def test_sigma_rules_match_unmodified_raw_vendor_json_without_parser() -> None:
    """Seat 4 real-wire test: raw AWS CloudTrail, Okta, and Entra ID JSON must match
    Sigma YAML rules directly with zero parser pre-normalization."""
    # Raw unmodified AWS CloudTrail JSON (FilterLogEvents secret search + DryRun + CyberStrikeAI userData/SSM)
    raw_cloudtrail = [
        {
            "eventVersion": "1.09",
            "eventSource": "logs.amazonaws.com",
            "eventName": "FilterLogEvents",
            "requestParameters": {"filterPattern": "password OR AKIA"},
        },
        {
            "eventVersion": "1.09",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "RunInstances",
            "errorCode": "Client.DryRunOperation",
        },
        {
            "eventVersion": "1.09",
            "eventSource": "ec2.amazonaws.com",
            "eventName": "DescribeInstanceAttribute",
            "userIdentity": {"arn": "arn:aws:sts::111122223333:assumed-role/WebRole/i-0123456789abcdef0"},
            "requestParameters": {"attribute": "userData", "instanceId": "i-0123456789abcdef0"},
        },
        {
            "eventVersion": "1.09",
            "eventSource": "ssm.amazonaws.com",
            "eventName": "GetParametersByPath",
            "requestParameters": {"path": "/prod/", "withDecryption": True},
        },
        {
            "eventVersion": "1.09",
            "eventSource": "ssm.amazonaws.com",
            "eventName": "SendCommand",
            "requestParameters": {"documentName": "AWS-RunShellScript"},
        },
    ]
    cw_rule = yaml.safe_load((RULES_DIR / "artex_aws_cloudwatch_and_dryrun_sweep.yml").read_text(encoding="utf-8"))
    cs_rule = yaml.safe_load(
        (RULES_DIR / "artex_aws_cyberstrikeai_userdata_ssm_and_ec2_role.yml").read_text(encoding="utf-8")
    )
    assert evaluate_sigma_rule_on_events(cw_rule, raw_cloudtrail) == 2
    assert evaluate_sigma_rule_on_events(cs_rule, raw_cloudtrail) == 3

    # Raw unmodified Okta System Log JSON
    raw_okta = [
        {
            "eventType": "user.mfa.okta_verify.deny_push",
            "outcome": {"result": "FAILURE", "reason": "VERIFICATION_ERROR"},
            "debugContext": {"debugData": {"requestUri": "/api/v1/authn/factors/verify"}},
        },
        {
            "eventType": "user.session.start",
            "outcome": {"result": "FAILURE", "reason": "INVALID_CREDENTIALS"},
            "debugContext": {"debugData": {"requestUri": "/api/v1/authn"}},
        },
    ]
    okta_rule = yaml.safe_load((RULES_DIR / "artex_okta_mfa_fatigue_and_authn_spray.yml").read_text(encoding="utf-8"))
    assert evaluate_sigma_rule_on_events(okta_rule, raw_okta) == 2

    # Raw unmodified Microsoft Entra ID SigninLogs + AuditLogs JSON
    raw_entra = [
        {
            "servicePrincipalName": "sp-backup",
            "status": {"errorCode": 7000215, "failureReason": "Invalid client secret"},
        },
        {
            "operationName": "Add service principal credentials",
            "result": "success",
        },
    ]
    entra_rule = yaml.safe_load(
        (RULES_DIR / "artex_entra_sp_secret_abuse_and_mfa_tampering.yml").read_text(encoding="utf-8")
    )
    assert evaluate_sigma_rule_on_events(entra_rule, raw_entra) == 2
