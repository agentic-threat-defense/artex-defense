"""Unit and false-positive guard tests for 2026-11-22 Watchtower intelligence updates."""

from __future__ import annotations

import json
from pathlib import Path

from artex_defense.detectors import scan_telemetry_file


def test_dragos_cloudtrail_artex_agent_and_judge_uas_detected_without_smartex_fp(tmp_path: Path) -> None:
    # TP: Dragos AWS CloudTrail canary-key UAs (`artex-agent`, `artex-judge-r121`)
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

    # FP Guard: `smartex-agent/1.0` and `smartex-judge-prod` must NEVER trigger (even across bursts)
    benign = [
        {
            "timestamp": f"2026-11-22T08:00:0{i}Z",
            "source_host": "198.51.100.40",
            "actor": "198.51.100.40",
            "event_type": "http",
            "surface": "web_portal",
            "http_method": "GET",
            "http_path": "/login",
            "user_agent": "smartex-agent/1.0" if i % 2 == 0 else "smartex-judge-prod",
            "status_code": 200,
        }
        for i in range(5)
    ]
    p_fp = tmp_path / "smartex_benign.jsonl"
    p_fp.write_text("\n".join(json.dumps(e) for e in benign) + "\n", encoding="utf-8")
    assert scan_telemetry_file(p_fp) == []


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
    # TP 1: AI coding/agent shell directly launching nmap -> flagged at hunt tier (55)
    # TP 2: AI coding agent launching bash -c 'nuclei ...' -> flagged at hunt tier (55)
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
        },
        {
            "timestamp": "2026-11-22T07:00:15Z",
            "source_host": "dev-box-08",
            "actor": "jdoe",
            "event_type": "process",
            "surface": "endpoint",
            "process": "/bin/bash",
            "parent_process": "claude",
            "command_line": "bash -c 'nuclei -u https://target.local'",
            "status_code": 0,
        },
    ]
    p_atk = tmp_path / "ai_agent_offensive.jsonl"
    p_atk.write_text("\n".join(json.dumps(e) for e in attack) + "\n", encoding="utf-8")
    cands = scan_telemetry_file(p_atk)
    assert len(cands) == 2
    for cand in cands:
        assert "ai_agent_spawns_offensive_tool" in cand.reasons
        assert cand.alert_tier == "hunt"

    # FP Guard: Normal developer commands (including commit messages, grep queries, pytest -k filters,
    # and non-agent grep mentioning `/claude` + `hydra`) MUST produce 0 hits
    benign = [
        {
            "timestamp": "2026-11-22T07:10:01Z",
            "source_host": "dev-box-07",
            "actor": "jdoe",
            "event_type": "process",
            "surface": "endpoint",
            "process": "/usr/bin/git",
            "parent_process": "claude",
            "command_line": "git commit -m 'fix nxc parser'",
            "status_code": 0,
        },
        {
            "timestamp": "2026-11-22T07:10:15Z",
            "source_host": "dev-box-07",
            "actor": "jdoe",
            "event_type": "process",
            "surface": "endpoint",
            "process": "/usr/bin/grep",
            "parent_process": "codex",
            "command_line": "grep -rn hydra src/",
            "status_code": 0,
        },
        {
            "timestamp": "2026-11-22T07:10:30Z",
            "source_host": "dev-box-07",
            "actor": "jdoe",
            "event_type": "process",
            "surface": "endpoint",
            "process": "/usr/bin/pytest",
            "parent_process": "opencode",
            "command_line": "pytest -k chisel",
            "status_code": 0,
        },
        {
            "timestamp": "2026-11-22T07:10:45Z",
            "source_host": "dev-box-07",
            "actor": "jdoe",
            "event_type": "process",
            "surface": "endpoint",
            "process": "/usr/bin/grep",
            "parent_process": "/usr/bin/bash",
            "command_line": "grep hydra /home/jdoe/claude",
            "status_code": 0,
        },
        {
            "timestamp": "2026-11-22T07:11:00Z",
            "source_host": "dev-box-07",
            "actor": "jdoe",
            "event_type": "process",
            "surface": "endpoint",
            "process": "/bin/bash",
            "parent_process": "claude",
            "command_line": "bash -c 'git commit -m \"fix nxc parser\"'",
            "status_code": 0,
        },
    ]
    p_fp = tmp_path / "ai_agent_benign_dev.jsonl"
    p_fp.write_text("\n".join(json.dumps(e) for e in benign) + "\n", encoding="utf-8")
    assert scan_telemetry_file(p_fp) == []
