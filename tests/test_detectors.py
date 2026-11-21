"""Unit tests for Stage 1 deterministic DuckDB + Python behavioral & artifact detectors."""

from pathlib import Path

from artex_defense.detectors import scan_telemetry_file

FIXTURE = Path(__file__).parent / "fixtures" / "sample_telemetry.jsonl"


def test_scan_separates_baseline_from_synthetic_agentic_windows() -> None:
    candidates = scan_telemetry_file(FIXTURE)
    hosts = {c.source_host for c in candidates}

    # Normal human-paced baseline traffic should NOT be flagged
    assert "wkstn-alice" not in hosts

    # Synthetic machine-speed burst + artifact + EDR probe + LLM egress window MUST be flagged
    assert "edge-portal-01" in hosts
    edge = next(c for c in candidates if c.source_host == "edge-portal-01")
    assert "machine_speed_burst" in edge.reasons
    assert "low_jitter_programmatic_cadence" in edge.reasons
    assert "automated_error_retry_loop" in edge.reasons
    assert "known_artex_artifact" in edge.reasons
    assert "agentic_default_port" in edge.reasons
    assert "llm_api_egress" in edge.reasons
    assert "edr_sensor_enumeration" in edge.reasons
    assert edge.cadence.event_count == 11
    assert edge.cadence.mean_interval_sec is not None and edge.cadence.mean_interval_sec < 1.5

    # Synthetic Cloud/IAM privilege burst MUST be flagged
    assert "entra-audit" in hosts
    iam = next(c for c in candidates if c.source_host == "entra-audit")
    assert "cloud_iam_privilege_burst" in iam.reasons


def test_bloodalchemy_and_artex_config_proxy_artifacts_detected(tmp_path: Path) -> None:
    log_file = tmp_path / "ba_test.jsonl"
    log_file.write_text(
        "\n".join(
            [
                '{"timestamp": "2026-11-20T12:00:00Z", "source_host": "srv-01", "actor": "svc", "event_type": "process", "process": "rundll32.exe", "command_line": "rundll32.exe graphics-hook-filter64.dll,Init"}',
                '{"timestamp": "2026-11-20T12:00:02Z", "source_host": "srv-01", "actor": "svc", "event_type": "http", "dest_host": "api.xcai.com", "http_path": "/Inform/logger/check", "status_code": 200}',
                '{"timestamp": "2026-11-20T12:00:04Z", "source_host": "srv-01", "actor": "svc", "event_type": "file", "command_line": "type artex_config.json"}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    candidates = scan_telemetry_file(log_file)
    assert len(candidates) == 1
    c = candidates[0]
    assert "known_artex_artifact" in c.reasons
    assert "llm_api_egress" in c.reasons
    indicators = " ".join(c.matched_indicators)
    assert "graphics-hook-filter64.dll" in indicators
    assert "/Inform/logger/" in indicators
    assert "artex_config.json" in indicators
    assert "xcai.com" in indicators


def test_unit42_canary_spec_targeting_and_write_readback_detected(tmp_path: Path) -> None:
    log_file = tmp_path / "unit42_test.jsonl"
    log_file.write_text(
        "\n".join(
            [
                '{"timestamp": "2026-11-20T13:00:00Z", "source_host": "31.40.205.155", "actor": "zz_no_such_user_9f3a", "event_type": "http", "http_method": "GET", "http_path": "/openapi.json", "user_agent": "Mozilla/5.0 (security-testing; authorized)", "status_code": 200}',
                '{"timestamp": "2026-11-20T13:00:02Z", "source_host": "31.40.205.155", "actor": "zz_no_such_user_9f3a", "event_type": "http", "http_method": "PUT", "http_path": "/api/v1/update-documents", "status_code": 422}',
                '{"timestamp": "2026-11-20T13:00:05Z", "source_host": "31.40.205.155", "actor": "zz_no_such_user_9f3a", "event_type": "http", "http_method": "PUT", "http_path": "/api/v1/update-documents", "status_code": 200}',
                '{"timestamp": "2026-11-20T13:00:06Z", "source_host": "31.40.205.155", "actor": "zz_no_such_user_9f3a", "event_type": "http", "http_method": "GET", "http_path": "/api/v1/update-documents", "status_code": 200}',
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    candidates = scan_telemetry_file(log_file)
    assert len(candidates) == 1
    reasons = set(candidates[0].reasons)
    assert "unit42_agentic_canary_probe" in reasons
    assert "spec_driven_api_targeting" in reasons
    assert "write_then_readback_verification" in reasons
    assert "agentic_user_agent_burst" in reasons
