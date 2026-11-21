"""Proof that Zero-IOC adversarial evasion scenarios contain zero static IOCs and are caught purely via behavior."""

from pathlib import Path

from artex_defense.detectors import scan_telemetry_file
from artex_defense.simulator import generate_synthetic_suite

FORBIDDEN_STATIC_IOC_TOKENS: tuple[str, ...] = (
    "artex",
    "artx5v",
    "norma",
    "scopeweaver",
    "antifox",
    "bloodalchemy",
    "graphics-hook",
    "8787",
    "8788",
    "8790",
    "api.deepseek",
    "api.anthropic",
    "api.openai",
    "xcai",
    "lanmao",
    "csfalcon",
    "sentinelagent",
    "windefend",
    "zz_no_such_user",
    "zzq.",
    "zzzrandom",
    "nuclei",
    "headlesschrome",
    "python-httpx",
    "go-http-client",
    "webhook.site",
    "dnslog.cn",
    "/v1/messages",
    "/v1/chat/completions",
)

STATIC_DETECTION_REASONS: set[str] = {
    "known_artex_artifact",
    "artex_console_or_host_forensics",
    "llm_api_egress",
    "webhook_exfil_egress",
    "agentic_default_port",
    "agentic_user_agent_burst",
    "edr_sensor_enumeration",
    "unit42_agentic_canary_probe",
}


def test_zero_ioc_evasion_scenarios_are_100_percent_behavioral(tmp_path: Path) -> None:
    manifest = generate_synthetic_suite(tmp_path)
    zero_ioc_entries = {name: meta for name, meta in manifest.items() if meta.get("zero_ioc")}

    assert len(zero_ioc_entries) == 4, f"Expected 4 Zero-IOC scenarios, got {list(zero_ioc_entries)}"

    for name, meta in zero_ioc_entries.items():
        path = Path(meta["path"])
        raw_text = path.read_text(encoding="utf-8").lower()

        leaked_tokens = [tok for tok in FORBIDDEN_STATIC_IOC_TOKENS if tok in raw_text]
        assert not leaked_tokens, f"{name} leaked static IOC tokens: {leaked_tokens}"

        candidates = scan_telemetry_file(path)
        assert candidates, f"{name} was NOT detected by behavioral detectors"

        observed_reasons = {r for c in candidates for r in c.reasons}
        static_hits = observed_reasons & STATIC_DETECTION_REASONS
        assert not static_hits, (
            f"{name} unexpectedly fired static reasons {static_hits} instead of pure behavioral detection"
        )

        missing = [r for r in meta["expected_reasons"] if r not in observed_reasons]
        assert not missing, f"{name} missing expected behavioral reasons {missing} (got {observed_reasons})"


def test_ja4_proxy_collapse_multi_ua_catches_recording_proxy_and_avoids_swg_fp(tmp_path: Path) -> None:
    """Validate single-JA4 recording-proxy TLS collapse vs. benign corporate forward proxy (SWG)."""
    import json

    # 1. True Positive: Zero-IOC agent routing curl + python + spoofed browser through one Go recording proxy
    # (1 constant JA4, zero JA4H logged, zero static ARTEX strings)
    proxy_events = [
        {
            "timestamp": "2026-11-21T18:00:01Z",
            "surface": "web_portal",
            "source_ip": "198.51.100.77",
            "dest_host": "portal.example.org",
            "http_method": "GET",
            "http_path": "/api/v1/users",
            "user_agent": "curl/8.5.0",
            "ja4": "t13d190900_9dc949149365_97f8aa674fd9",
            "status_code": 403,
        },
        {
            "timestamp": "2026-11-21T18:00:03Z",
            "surface": "web_portal",
            "source_ip": "198.51.100.77",
            "dest_host": "portal.example.org",
            "http_method": "GET",
            "http_path": "/api/v1/internal-config",
            "user_agent": "python-urllib3/2.2.1",
            "ja4": "t13d190900_9dc949149365_97f8aa674fd9",
            "status_code": 404,
        },
        {
            "timestamp": "2026-11-21T18:00:05Z",
            "surface": "web_portal",
            "source_ip": "198.51.100.77",
            "dest_host": "portal.example.org",
            "http_method": "POST",
            "http_path": "/api/v1/admin/export",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0 Safari/537.36",
            "ja4": "t13d190900_9dc949149365_97f8aa674fd9",
            "status_code": 405,
        },
    ]
    tp_path = tmp_path / "proxy_collapse_tp.jsonl"
    tp_path.write_text("\n".join(json.dumps(e) for e in proxy_events) + "\n", encoding="utf-8")

    tp_cands = scan_telemetry_file(tp_path)
    assert tp_cands, "Expected recording-proxy TLS collapse to trigger detection"
    tp_reasons = {r for c in tp_cands for r in c.reasons}
    assert "ja4_proxy_collapse_multi_ua" in tp_reasons
    assert not (tp_reasons & STATIC_DETECTION_REASONS)
    assert max(c.risk_score for c in tp_cands) >= 70

    # 2. True Negative: Benign corporate forward proxy / SWG (1 proxy JA4, multiple employee browsers,
    # asset favicon 404s + 1 employee hitting 3 broken docs links) must NOT fire ja4_proxy_collapse_multi_ua
    swg_events = [
        {
            "timestamp": "2026-11-21T18:05:01Z",
            "surface": "web_portal",
            "source_ip": "203.0.113.88",
            "dest_host": "portal.example.org",
            "http_method": "GET",
            "http_path": "/home",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/129.0.0.0 Safari/537.36",
            "ja4": "t13d1516h2_8daaf6152771_b0da82dd1658",
            "status_code": 200,
        },
        {
            "timestamp": "2026-11-21T18:05:02Z",
            "surface": "web_portal",
            "source_ip": "203.0.113.88",
            "dest_host": "portal.example.org",
            "http_method": "GET",
            "http_path": "/favicon.ico",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
            "ja4": "t13d1516h2_8daaf6152771_b0da82dd1658",
            "status_code": 404,
        },
        {
            "timestamp": "2026-11-21T18:05:04Z",
            "surface": "web_portal",
            "source_ip": "203.0.113.88",
            "dest_host": "portal.example.org",
            "http_method": "GET",
            "http_path": "/dashboard",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0 Edg/130.0.0.0",
            "ja4": "t13d1516h2_8daaf6152771_b0da82dd1658",
            "status_code": 200,
        },
        {
            "timestamp": "2026-11-21T18:05:06Z",
            "surface": "web_portal",
            "source_ip": "203.0.113.88",
            "dest_host": "portal.example.org",
            "http_method": "GET",
            "http_path": "/docs/old-faq",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36",
            "ja4": "t13d1516h2_8daaf6152771_b0da82dd1658",
            "status_code": 404,
        },
        {
            "timestamp": "2026-11-21T18:05:08Z",
            "surface": "web_portal",
            "source_ip": "203.0.113.88",
            "dest_host": "portal.example.org",
            "http_method": "GET",
            "http_path": "/docs/old-guide",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36",
            "ja4": "t13d1516h2_8daaf6152771_b0da82dd1658",
            "status_code": 404,
        },
        {
            "timestamp": "2026-11-21T18:05:10Z",
            "surface": "web_portal",
            "source_ip": "203.0.113.88",
            "dest_host": "portal.example.org",
            "http_method": "GET",
            "http_path": "/docs/old-api",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0 Safari/537.36",
            "ja4": "t13d1516h2_8daaf6152771_b0da82dd1658",
            "status_code": 404,
        },
    ]
    swg_path = tmp_path / "benign_swg_tn.jsonl"
    swg_path.write_text("\n".join(json.dumps(e) for e in swg_events) + "\n", encoding="utf-8")

    swg_cands = scan_telemetry_file(swg_path)
    swg_reasons = {r for c in swg_cands for r in c.reasons}
    assert "ja4_proxy_collapse_multi_ua" not in swg_reasons
