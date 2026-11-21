"""Unit tests for the offline TaskID staging & transcript analyzer."""

from pathlib import Path

from artex_defense.task_analyzer import analyze_task_artifacts


def test_analyze_task_artifacts_extracts_retry_chains_and_sanitizes(tmp_path: Path) -> None:
    sample = tmp_path / "synthetic_task_log.jsonl"
    sample.write_text(
        "\n".join(
            [
                '{"TaskID": "T-101", "tool": "WebFetch", "command": "curl https://portal.corp.local/api/admin", "status": "failed", "output": "403 Forbidden from 10.20.30.40"}',
                '{"TaskID": "T-101", "tool": "WebFetch", "command": "curl https://portal.corp.local/.env", "status": "succeeded", "output": "200 OK api_key=sk-ant-1234567890abcdef123456"}',
                '{"TaskID": "T-102", "tool": "shell", "command": "sc query CSFalconService", "status": "succeeded", "output": "RUNNING"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = analyze_task_artifacts(sample, sanitize=True)
    assert result["unique_task_ids"] == 2
    assert result["total_task_events"] == 3
    assert result["outcomes"]["failed"] == 1
    assert result["outcomes"]["succeeded"] == 2
    assert "curl" in result["observed_tools"]
    assert "sc query" in result["observed_tools"]
    assert len(result["retry_mutation_chains"]) == 1
    assert result["retry_mutation_chains"][0]["task_id"] == "T-101"
    assert result["retry_mutation_chains"][0]["resolved"] is True

    # Ensure sensitive IPs, URLs, and secrets are sanitized
    blob = str(result)
    assert "10.20.30.40" not in blob
    assert "sk-ant-" not in blob
    assert "hxxps://" in blob
    assert "[REDACTED_SECRET]" in blob


def test_analyze_task_artifacts_recognizes_artex_intent_ids(tmp_path: Path) -> None:
    intent_dir = tmp_path / "i12345"
    intent_dir.mkdir()
    (intent_dir / "trace.jsonl").write_text(
        "\n".join(
            [
                '{"tool": "ARTEX-worker/1.0", "command": "nuclei -u https://vpn.corp.local", "status": "failed", "output": "403"}',
                '{"tool": "artex-readonly/1.0", "command": "curl https://vpn.corp.local/vpn/index.html", "status": "succeeded", "output": "200"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = analyze_task_artifacts(tmp_path, sanitize=True)
    assert result["unique_task_ids"] == 1
    assert result["retry_mutation_chains"][0]["task_id"] == "i12345"
    assert result["retry_mutation_chains"][0]["resolved"] is True
