"""Unit and false-positive guard tests for 2026-11-22 Watchtower intelligence gaps."""

from __future__ import annotations

import json
from pathlib import Path

from artex_defense.detectors import scan_telemetry_file


def test_dragos_cloudtrail_artex_agent_and_judge_uas_detected(tmp_path: Path) -> None:
    events = [
        {
            "eventVersion": "1.09",
            "eventTime": "2026-11-22T07:50:01Z",
            "eventSource": "sts.amazonaws.com",
            "eventName": "GetCallerIdentity",
            "sourceIPAddress": "203.0.113.190",
            "userAgent": "artex-agent",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/canary-key"},
        },
        {
            "eventVersion": "1.09",
            "eventTime": "2026-11-22T07:50:05Z",
            "eventSource": "sts.amazonaws.com",
            "eventName": "GetCallerIdentity",
            "sourceIPAddress": "203.0.113.191",
            "userAgent": "artex-judge-r121",
            "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/canary-key"},
        },
    ]
    p = tmp_path / "dragos_canary_uas.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")

    cands = scan_telemetry_file(p)
    assert len(cands) == 2
    for c in cands:
        assert "agentic_user_agent_burst" in c.reasons
        assert c.risk_score >= 70


def test_litellm_mcp_rest_rce_probe_detected(tmp_path: Path) -> None:
    events = [
        {
            "timestamp": "2026-11-22T06:00:01Z",
            "source_host": "198.51.100.180",
            "actor": "198.51.100.180",
            "event_type": "http",
            "surface": "web_portal",
            "http_method": "GET",
            "http_path": "/mcp-rest/test/tools/list",
            "user_agent": "python-requests/2.32.3",
            "status_code": 404,
        },
        {
            "timestamp": "2026-11-22T06:00:03Z",
            "source_host": "198.51.100.180",
            "actor": "198.51.100.180",
            "event_type": "http",
            "surface": "web_portal",
            "http_method": "GET",
            "http_path": "/v1/models",
            "user_agent": "python-requests/2.32.3",
            "status_code": 401,
        },
    ]
    p = tmp_path / "litellm_mcp_rce.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")

    cands = scan_telemetry_file(p)
    assert len(cands) == 1
    assert "graphql_or_ai_mcp_discovery_probe" in cands[0].reasons


def test_ai_agent_spawning_offensive_tool_vs_benign_dev_commands(tmp_path: Path) -> None:
    # TP: AI coding/agent shell launching nmap/nuclei -> flagged at hunt tier (55)
    attack = [
        {
            "timestamp": "2026-11-22T07:00:01Z",
            "source_host": "dev-box-07",
            "actor": "jdoe",
            "event_type": "process",
            "surface": "endpoint",
            "process": "/usr/bin/nmap",
            "parent_process": "/home/jdoe/.claude/shell-snapshots/snapshot-bash-123.sh",
            "command_line": "nmap -sV -p 5985,5986 10.20.0.0/24",
            "status_code": 0,
        }
    ]
    p_atk = tmp_path / "ai_agent_offensive.jsonl"
    p_atk.write_text("\n".join(json.dumps(e) for e in attack) + "\n", encoding="utf-8")
    cands = scan_telemetry_file(p_atk)
    assert len(cands) == 1
    assert "ai_agent_spawns_offensive_tool" in cands[0].reasons
    assert cands[0].alert_tier == "hunt"

    # FP Guard: Normal developer using Claude/OpenCode for git, pytest, npm, curl -> 0 hits
    benign = [
        {
            "timestamp": "2026-11-22T07:10:01Z",
            "source_host": "dev-box-07",
            "actor": "jdoe",
            "event_type": "process",
            "surface": "endpoint",
            "process": "/usr/bin/git",
            "parent_process": "/home/jdoe/.claude/shell-snapshots/snapshot-bash-123.sh",
            "command_line": "git status",
            "status_code": 0,
        },
        {
            "timestamp": "2026-11-22T07:10:20Z",
            "source_host": "dev-box-07",
            "actor": "jdoe",
            "event_type": "process",
            "surface": "endpoint",
            "process": "pytest",
            "parent_process": "claude",
            "command_line": "pytest tests/unit",
            "status_code": 0,
        },
    ]
    p_fp = tmp_path / "ai_agent_benign_dev.jsonl"
    p_fp.write_text("\n".join(json.dumps(e) for e in benign) + "\n", encoding="utf-8")
    assert scan_telemetry_file(p_fp) == []
