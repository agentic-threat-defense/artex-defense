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
