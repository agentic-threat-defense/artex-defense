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
