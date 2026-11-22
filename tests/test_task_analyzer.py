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


def test_analyze_task_artifacts_plain_text_tool_and_cross_intent_retry_chains(tmp_path: Path) -> None:
    plain_log = tmp_path / "plain_intents.log"
    plain_log.write_text(
        "\n".join(
            [
                '2026-11-22T12:00:01Z intent=i104 tool=nuclei cmd="nuclei -u hxxp://target.local" status=403',
                '2026-11-22T12:00:05Z intent=i105 tool=curl cmd="curl hxxp://target.local/admin" status=200',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    res = analyze_task_artifacts(plain_log, sanitize=False)
    assert res["total_task_events"] == 2
    assert res["sample_tasks"][0]["tool"] == "nuclei"
    assert res["sample_tasks"][0]["command"] == "nuclei -u hxxp://target.local"
    assert res["sample_tasks"][1]["tool"] == "curl"
    assert res["sample_tasks"][1]["command"] == "curl hxxp://target.local/admin"
    assert len(res["retry_mutation_chains"]) == 1
    chain = res["retry_mutation_chains"][0]
    assert chain["task_id"] == "i104->i105"
    assert chain["attempts"] == 2
    assert chain["resolved"] is True

    # Interleaved cross-intent retries across two different targets must BOTH be detected cleanly
    interleaved = tmp_path / "interleaved.log"
    interleaved.write_text(
        "\n".join(
            [
                '2026-11-22T12:01:01Z intent=i301 tool=nuclei cmd="nuclei -u https://alpha.corp.local" status=403',
                '2026-11-22T12:01:02Z intent=i401 tool=nuclei cmd="nuclei -u https://beta.corp.local" status=403',
                '2026-11-22T12:01:03Z intent=i302 tool=curl cmd="curl https://alpha.corp.local/admin" status=200',
                '2026-11-22T12:01:04Z intent=i402 tool=curl cmd="curl https://beta.corp.local/admin" status=200',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    ires = analyze_task_artifacts(interleaved, sanitize=False)
    chain_ids = {c["task_id"] for c in ires["retry_mutation_chains"]}
    assert chain_ids == {"i301->i302", "i401->i402"}
    assert all(c["resolved"] is True for c in ires["retry_mutation_chains"])

    # Negative check: sequential events on DIFFERENT targets (even with same tool) must NOT falsely merge
    unrelated = tmp_path / "unrelated.log"
    unrelated.write_text(
        "\n".join(
            [
                '2026-11-22T12:02:01Z intent=i501 tool=curl cmd="curl https://host-a.corp.local/login" status=403',
                '2026-11-22T12:02:04Z intent=i502 tool=curl cmd="curl https://host-b.corp.local/health" status=200',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    ures = analyze_task_artifacts(unrelated, sanitize=False)
    assert ures["retry_mutation_chains"] == []
