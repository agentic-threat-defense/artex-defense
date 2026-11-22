"""Permanent rule-pack hygiene regression tests across YARA, Suricata, Zeek, SIEM templates, and Intel Hunting."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
RULES_ROOT = REPO_ROOT / "rules"


def test_yara_rules_enforce_filesize_bounds_and_avoid_fp_traps() -> None:
    yara_files = sorted((RULES_ROOT / "yara").glob("*.yar"))
    assert len(yara_files) == 3

    for yf in yara_files:
        text = yf.read_text(encoding="utf-8")
        assert "filesize <" in text, f"{yf.name} missing upper filesize bound"
        assert '$name_artex = "artex"' not in text, f"{yf.name} re-introduced bare 'artex' substring trap"
        assert '$name_luck = "LUCK"' not in text, f"{yf.name} re-introduced bare 'LUCK' substring trap"
        assert "or $name_bloodalchemy" not in text, f"{yf.name} matches vendor name BLOODALCHEMY unconditionally"

    livehunt = (RULES_ROOT / "yara" / "gti_livehunt_artex_payloads_transcripts.yar").read_text(encoding="utf-8")
    assert "uint16(0) == 0x5A4D" in livehunt, "Livehunt BLOODALCHEMY branch must be PE-gated"
    assert "xcai.pro" in livehunt

    retrohunt = (RULES_ROOT / "yara" / "gti_retrohunt_vaporpanda_bloodalchemy_artex.yar").read_text(encoding="utf-8")
    assert "pe.is_pe" in retrohunt
    assert "xcai.pro" in retrohunt
    assert "filesize > 1KB and filesize < 35MB and (" not in retrohunt, "Global filesize > 1KB drops <1KB configs"


def test_suricata_rules_have_valid_classtypes_buffers_sids_and_no_fp_traps() -> None:
    suricata_path = RULES_ROOT / "network" / "artex_edge_and_harness.rules"
    text = suricata_path.read_text(encoding="utf-8")
    rule_lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    assert len(rule_lines) >= 12

    # Stock Suricata classification.config never defines `classtype:exfiltration;`
    assert "classtype:exfiltration;" not in text
    # Avoid matching "normal" in User-Agents
    assert "|norma)" not in text
    # Avoid deprecated `threshold:` keyword in favor of `detection_filter:`
    assert "threshold:" not in text

    seen_sids: set[str] = set()
    for ln in rule_lines:
        assert "flow:" in ln, f"Suricata rule missing flow: {ln[:80]}"
        sid_m = re.search(r"\bsid:(\d+);", ln)
        assert sid_m is not None, f"Suricata rule missing sid: {ln[:80]}"
        sid = sid_m.group(1)
        assert sid not in seen_sids, f"Duplicate Suricata sid:{sid}"
        seen_sids.add(sid)

        # Every HTTP rule with PCRE must specify an explicit HTTP sticky buffer
        if ln.startswith("alert http ") and "pcre:" in ln:
            assert any(
                buf in ln for buf in ("http.uri;", "http.user_agent;", "http.header;", "http.response_body;")
            ), f"HTTP PCRE rule missing sticky buffer: {ln[:80]}"


def test_zeek_script_decouples_c2_relays_and_bounds_notice_identifiers() -> None:
    zeek_path = RULES_ROOT / "network" / "artex_agentic_cadence.zeek"
    text = zeek_path.read_text(encoding="utf-8")

    assert "Malicious_LLM_Relay_C2" in text
    assert "malicious_llm_relay_suffixes" in text
    assert "commercial_llm_api_suffixes" in text
    # Must never embed raw attacker-controlled UA value directly in $identifier
    assert "$identifier=cat(c$id$orig_h, value)" not in text
    # Must guard HTTP 4xx burst against 5xx server outages and static assets
    assert "code < 500" in text
    assert "static_asset_uri_pattern" in text
    assert "artex.http_4xx_uris" in text


def test_handwritten_siem_queries_pass_syntax_and_fp_linter() -> None:
    cql = (RULES_ROOT / "queries" / "crowdstrike_logscale_cql.cql").read_text(encoding="utf-8")
    assert "RemotePort IN [" not in cql, "Invalid LogScale CQL `IN [...]` syntax"
    assert "ComputerName!=/" not in cql, "Invalid LogScale CQL `!= /regex/` syntax"
    assert "in(RemotePort, values=" in cql
    assert "not ComputerName=/" in cql

    eql = (RULES_ROOT / "queries" / "elastic_ech_eql.eql").read_text(encoding="utf-8")
    assert 'RLIKE "(?i)' not in eql, "ES|QL Lucene Automaton RLIKE does not support (?i) flag"
    assert 'url.path : ("*/Inform/logger/*", "*?artex=*"' not in eql, "ECS url.path excludes query strings"
    assert "BY aws.cloudtrail.user_identity.arn, source.ip, event.action" not in eql, "Grouping by event.action forces COUNT_DISTINCT=1"

    kql = (RULES_ROOT / "queries" / "microsoft_mde_kql.kql").read_text(encoding="utf-8")
    assert 'ResultType in ("500121", "50074")' not in kql, "Entra 50074 is normal MFA challenge, not failure"
    assert 'ResultType == "500121"' in kql

    s1ql = (RULES_ROOT / "queries" / "sentinelone_s1ql.s1ql").read_text(encoding="utf-8")
    assert "| bucket 30s" not in s1ql, "Invalid S1QL PowerQuery syntax; use timebucket()"
    assert "timebucket(" in s1ql
    assert "tgt.process.cmdline" in s1ql
    assert "src.process.parent.name" not in s1ql, "Inverted S1QL 2.0 parent/child lineage"


def test_passive_intel_hunt_queries_use_current_platform_syntax() -> None:
    md = (RULES_ROOT / "intel_hunting" / "enterprise_intel_hunt_queries.md").read_text(encoding="utf-8")
    assert "CONTAINS '" not in md and 'CONTAINS "' not in md, "HuntSQL uses LIKE/ILIKE, not CONTAINS"
    assert "services.http.response." not in md, "Update legacy Censys Search 2.0 paths to CenQL host.services"
    assert "raw_data.web.useragents:*norma/0.*" not in md, "GNQL slashes must be quoted"
    assert "raw_data.web.paths:*artex=*" not in md, "GNQL '=' must be quoted"


def test_sigma_rules_avoid_known_critical_fp_and_drift_regressions() -> None:
    # Unique UUIDs across all Sigma rules
    uuids: set[str] = set()
    for path in sorted((RULES_ROOT / "sigma").glob("*.yml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        uid = str(doc.get("id", ""))
        assert uid and uid not in uuids, f"Duplicate or empty Sigma UUID in {path.name}"
        uuids.add(uid)

    # vshell must not bare-substring match Visual Studio DevShell
    post_ad = (RULES_ROOT / "sigma" / "artex_post_exploit_ad_and_followon_c2.yml").read_text(encoding="utf-8")
    assert "- 'vshell'\n" not in post_ad
    assert "VsDevShell" in post_ad
    assert "wisp-c2" in post_ad

    # Malicious C2 relays must never be suppressed by workstation filter
    llm_rule = (RULES_ROOT / "sigma" / "artex_llm_api_egress.yml").read_text(encoding="utf-8")
    assert "selection_malicious_relay" in llm_rule
    assert "or selection_malicious_relay" in llm_rule

    # No synthetic Action left in webserver or Duo/Ping/GWS Sigma rules
    idp_rule = (RULES_ROOT / "sigma" / "artex_idp_duo_ping_gws_2fa_abuse.yml").read_text(encoding="utf-8")
    assert "Action|contains:" not in idp_rule
    unit42_rule = (RULES_ROOT / "sigma" / "artex_unit42_canary_and_spec_targeting.yml").read_text(encoding="utf-8")
    assert "Action|contains:" not in unit42_rule
    assert "- 'nonexistent-i'\n" not in unit42_rule
    assert "- 'artex='\n" not in unit42_rule

    # Web error-correction must exclude .env.example templates
    web_err = (RULES_ROOT / "sigma" / "artex_web_error_correction_burst.yml").read_text(encoding="utf-8")
    assert "/.env.example" in web_err

    # Webhook rule must not match toast.live / coast.live via contains
    webhook = (RULES_ROOT / "sigma" / "artex_webhook_exfil_and_norma_harness.yml").read_text(encoding="utf-8")
    assert "cs-host|contains:" not in webhook
    assert ".oast.live" in webhook

    # Linux staging compiler rule must exclude package managers (pip/dpkg/apt/cargo)
    linux_pivot = (RULES_ROOT / "sigma" / "artex_linux_staging_compiler_and_proxychains_pivot.yml").read_text(
        encoding="utf-8"
    )
    assert "filter_legit_builds" in linux_pivot
    assert "'/pip'" in linux_pivot and "'/dpkg'" in linux_pivot
