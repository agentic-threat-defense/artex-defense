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
        assert "FF 20 47 6F 20 62 75 69 6C 64 69 6E 66 3A" in text, f"{yf.name} missing stripped-Go buildinfo anchor"
        assert "0xBEBAFECA" in text, f"{yf.name} missing Universal/Fat Mach-O magic"
        assert "CyberStrikeAI" in text and "adaptixc2" in text and "wisp-c2" in text, f"{yf.name} missing CyberStrikeAI/C2 anchors"
        assert "ARTEX_WRITE_PROBE" in text and "E3 80 90 41 52 54 45 58" in text, f"{yf.name} missing Nov 2026 canary/audit anchors"
        assert "0x46445025" in text and "$doc_html" in text, f"{yf.name} missing PDF/HTML CTI report FP guard"

    livehunt = (RULES_ROOT / "yara" / "gti_livehunt_artex_payloads_transcripts.yar").read_text(encoding="utf-8")
    assert "uint16(0) == 0x5A4D" in livehunt, "Livehunt BLOODALCHEMY branch must be PE-gated"
    assert "xcai.pro" in livehunt
    assert "any of ($ba_dll, $ba_cfg, $ba_uri)" not in livehunt, "Livehunt Branch 1 must not match standalone /Inform/logger/"
    assert "any of ($mod_artex, $mod_norma, $art_yaml, $art_json)" not in livehunt, "Standalone artex.yaml/artex_config.json FPs on CTI reports"

    retrohunt = (RULES_ROOT / "yara" / "gti_retrohunt_vaporpanda_bloodalchemy_artex.yar").read_text(encoding="utf-8")
    assert "pe.is_pe" in retrohunt
    assert "xcai.pro" in retrohunt
    assert "filesize > 1KB and filesize < 35MB and (" not in retrohunt, "Global filesize > 1KB drops <1KB configs"
    assert "($ba_uri and any of ($ba_reg, $ba_path1, $ba_dll_br))" not in retrohunt, "Path A must not pair /Inform/logger/ with Internet Settings alone"
    assert "any of ($mod_artex, $mod_norma, $art_path1, $art_cfg1, $art_cfg2)" not in retrohunt, "Standalone artex.yaml/artex_config.json FPs on CTI reports"


def test_suricata_rules_have_valid_classtypes_buffers_sids_and_no_fp_traps() -> None:
    suricata_path = RULES_ROOT / "network" / "artex_edge_and_harness.rules"
    text = suricata_path.read_text(encoding="utf-8")
    rule_lines = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.strip().startswith("#")]
    assert len(rule_lines) >= 12

    # Stock Suricata classification.config never defines `classtype:exfiltration;`
    assert "classtype:exfiltration;" not in text
    # Avoid matching "normal" in User-Agents
    assert "|norma)" not in text
    # Avoid deprecated `threshold:type threshold` (use `detection_filter:`) and never use `detection_filter: count 1`
    # (which silently drops Match #1; single-event rate limiting must use `threshold:type limit`)
    assert "threshold:type threshold" not in text
    assert "detection_filter:track by_src, count 1," not in text

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
                buf in ln
                for buf in ("http.uri;", "http.user_agent;", "http.header;", "http.request_body;", "http.response_body;")
            ), f"HTTP PCRE rule missing sticky buffer: {ln[:80]}"

        # Unescaped semicolons inside pcre:"..." or content:"..." break Suricata's option parser
        for kw in ("pcre", "content"):
            for m in re.finditer(rf'{kw}:"((?:[^"\\]|\\.)*)"', ln):
                assert ";" not in m.group(1), f"Unescaped ';' inside Suricata {kw}: {ln[:100]}"

    # Hardened SID coverage and FP boundary assertions
    assert {"9100016", "9100017", "9100018", "9100019", "9100020", "9100021"}.issubset(seen_sids), (
        "Missing POST-body canary (9100016), IMDS wildcard DNS (9100017), SOAP OSExecute (9100018), "
        "SAPControl read (9100019), .htaccess PHP reactivation (9100020), or Ruby2Shell CVE-2026-132825 (9100021)"
    )
    sid21_line = next(ln for ln in rule_lines if "sid:9100021;" in ln)
    assert "charset=" in sid21_line and r"\xdf{4,}" in sid21_line, (
        "sid:9100021 must require BOTH legacy charset header AND >=4 consecutive 0xDF bytes (0 FP on German 'Straße')"
    )
    assert r"O=ARTEX(?:,|$)" in text, "sid:9100013 must enforce exact RDN boundary on O=ARTEX"
    assert "oast\\.(?:live|fun|me|pro|site|online)" in text, "sid:9100011 must include full Interactsh oast.* TLDs"
    assert "[8787,8788,8790,8890,18899]" in text, "sid:9100002 must include MCP port 18899"
    assert 'content:!"X-Zscaler"' in text, "sid:9100002 must guard against Zscaler proxy headers"
    # Verify sid:9100015 JWT alg:none regex matches key-reordered/mixed-case/spaced Base64URL headers without FP on RS256/HS256
    sid15_line = next(ln for ln in rule_lines if "sid:9100015;" in ln)
    sid15_pcre = re.search(r'pcre:"/(.+)/"', sid15_line)
    assert sid15_pcre is not None, "sid:9100015 must use case-sensitive PCRE (no /i flag on Base64)"
    jwt_re = re.compile(sid15_pcre.group(1))
    import base64

    def _b64u(raw: str) -> str:
        return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")

    for bad_hdr in (
        '{"alg":"none"}',
        '{"alg":"None"}',
        '{"alg":"NONE"}',
        '{"alg": "none"}',
        '{"typ":"JWT","alg":"none"}',
        '{"typ": "JWT", "alg": "none"}',
        '{"alg":"none","typ":"JWT"}',
        '{"kid":"1","alg":"none"}',
    ):
        assert jwt_re.search(f"Authorization: Bearer {_b64u(bad_hdr)}.eyJzdWIiOiIxIn0."), f"Missed JWT: {bad_hdr}"
    for good_hdr in (
        '{"alg":"HS256","typ":"JWT"}',
        '{"alg":"RS256","typ":"JWT"}',
        '{"typ":"JWT","alg":"RS256","kid":"none"}',
    ):
        assert not jwt_re.search(f"Authorization: Bearer {_b64u(good_hdr)}.eyJzdWIiOiIxIn0.sig"), f"FP JWT: {good_hdr}"


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
    assert 'to_upper(name) == "USER-AGENT"' in text, "HTTP/2 header names may be lowercase"
    assert "zscaler_zen_subnets" in text and "18899/tcp" in text
    assert "imds_wildcard_dns_pattern" in text
    assert "Agentic_ControlPlane_Or_Canary_URI" in text
    assert "commercial_llm_api_suffixes in query" in text, "DNS commercial LLM check covers TLS 1.3 ECH"


def _tier1_query_code(text: str) -> str:
    t1_block = text.split("TIER 2 —", 1)[0]
    return "\n".join(ln for ln in t1_block.splitlines() if not ln.lstrip().startswith("//"))


def test_handwritten_siem_queries_pass_syntax_and_fp_linter() -> None:
    cql = (RULES_ROOT / "queries" / "crowdstrike_logscale_cql.cql").read_text(encoding="utf-8")
    assert "TIER 1" in cql and "TIER 2" in cql, "CrowdStrike CQL must separate Tier 1 triage from Tier 2 hunts"
    assert "RemotePort IN [" not in cql, "Invalid LogScale CQL `IN [...]` syntax"
    assert "ComputerName!=/" not in cql, "Invalid LogScale CQL `!= /regex/` syntax"
    assert "in(RemotePort, values=[8787, 8788, 8790, 8890, 18899])" in cql
    assert 'in(#event_simpleName, values=["DnsRequest", "DnsLookup"])' in cql
    assert 'in(#event_simpleName, values=["PeFileWritten", "NewExecutableWritten", "ElfFileWritten", "FileWritten"])' in cql
    assert "ContextBaseFileName=/^ZSA/i" in cql, "CrowdStrike CQL must exclude Zscaler Client Connector on TCP 8890"
    assert "metadata\\.google\\.internal" in cql, "CrowdStrike CQL Query T2-C must exclude routine GCP metadata checks"
    assert "sort(hits, order=asc)" in cql, "CrowdStrike CQL hunts must use LFO ascending sort to avoid 200-row cap"
    assert "not ComputerName=/" in cql
    cql_t1 = _tier1_query_code(cql)
    assert "webhook" not in cql_t1.lower() and "8890" not in cql_t1, "Tier 1 CQL must not mix noisy ports/webhook.site with C2 domains"

    eql = (RULES_ROOT / "queries" / "elastic_ech_eql.eql").read_text(encoding="utf-8")
    assert "TIER 1" in eql and "TIER 2" in eql, "Elastic EQL must separate Tier 1 triage from Tier 2 hunts"
    assert 'RLIKE "(?i)' not in eql, "ES|QL Lucene Automaton RLIKE does not support (?i) flag"
    assert 'url.path : ("*/Inform/logger/*", "*?artex=*"' not in eql, "ECS url.path excludes query strings"
    assert "BY aws.cloudtrail.user_identity.arn, source.ip, event.action" not in eql, "Grouping by event.action forces COUNT_DISTINCT=1"
    assert 'event.category == "network"' in eql and "destination.ip != null" in eql
    assert "url.full :" in eql and "TO_LOWER(file.name) IN" in eql
    assert "process.name == null or not (destination.port == 8890 and process.name" in eql
    eql_t1 = _tier1_query_code(eql)
    assert "webhook.site" not in eql_t1 and "8890" not in eql_t1

    kql = (RULES_ROOT / "queries" / "microsoft_mde_kql.kql").read_text(encoding="utf-8")
    assert "TIER 1" in kql and "TIER 2" in kql, "MDE KQL must separate Tier 1 triage from Tier 2 hunts"
    assert 'ResultType in ("500121", "50074")' not in kql, "Entra 50074 is normal MFA challenge, not failure"
    assert 'ResultType == "500121"' in kql
    assert 'RemotePort == 8890 and InitiatingProcessFileName startswith "ZSA"' in kql
    assert 'ProcessCommandLine has "metadata.google.internal"' in kql
    assert '";", "&&"' not in kql, "KQL has_any() only matches alphanumeric terms, never pure punctuation"
    assert r'matches regex @"[;|&`]|\$\("' in kql
    assert 'DeviceType =~ "Server"' in kql, "MDE KQL server LLM hunt must use DeviceInfo server role"
    assert "union isfuzzy=true DeviceImageLoadEvents, DeviceFileEvents" in kql
    assert "/etc/passwd" in kql
    kql_t1 = _tier1_query_code(kql)
    assert "webhook" not in kql_t1.lower() and "8890" not in kql_t1

    s1ql = (RULES_ROOT / "queries" / "sentinelone_s1ql.s1ql").read_text(encoding="utf-8")
    assert "TIER 1" in s1ql and "TIER 2" in s1ql, "SentinelOne S1QL must separate Tier 1 triage from Tier 2 hunts"
    assert "| bucket 30s" not in s1ql, "Invalid S1QL PowerQuery syntax; use timebucket()"
    assert "timebucket(" in s1ql
    assert "tgt.process.cmdline" in s1ql
    assert "module.path contains:anycase" in s1ql
    assert "/etc/passwd" in s1ql
    assert "src.process.parent.name" not in s1ql, "Inverted S1QL 2.0 parent/child lineage"
    assert 'dst.port.number == 8890 AND src.process.name startsWith:anycase "ZSA"' in s1ql
    assert 'tgt.process.cmdline contains:anycase "metadata.google.internal"' in s1ql
    s1ql_t1 = _tier1_query_code(s1ql)
    assert "webhook" not in s1ql_t1.lower() and "8890" not in s1ql_t1


def test_passive_intel_hunt_queries_use_current_platform_syntax() -> None:
    md = (RULES_ROOT / "intel_hunting" / "enterprise_intel_hunt_queries.md").read_text(encoding="utf-8")
    assert "CONTAINS '" not in md and 'CONTAINS "' not in md, "HuntSQL uses LIKE/ILIKE, not CONTAINS"
    assert "services.http.response." not in md, "Update legacy Censys Search 2.0 paths to CenQL host.services"
    assert "host.services:(" in md, "CenQL multi-field service predicates must be scoped inside host.services:(...)"
    assert "18899" in md and "CyberStrikeAI" in md and "adaptixc2" in md
    assert "raw_data.web.useragents:*norma/0.*" not in md, "GNQL slashes must be quoted"
    assert "raw_data.web.paths:*artex=*" not in md, "GNQL '=' must be quoted"
    assert 'raw_data.http.useragent:"*artex-enrich/*"' in md, "Include native GNQL v3 raw_data.http.useragent field"
    assert 'raw_data.http.path:"*artex=*"' in md, "Include native GNQL v3 raw_data.http.path field"
    assert "1_CRITICAL_IMDS_SSRF" in md and "is_workstation" in md, "Splunk wildcard-DNS hunt must separate dev workstations from server SSRF"

    adj = (RULES_ROOT / "intel_hunting" / "adjacent_china_nexus_edge_and_idp_hunts.md").read_text(encoding="utf-8")
    assert "$left.ServicePrincipalId == $right.TargetSPId" in adj, "Sentinel SP hunt must join on ServicePrincipalId first"
    assert "PriorEvents >= 5000 and EventsLastHour >= 200" in adj, "ASA syslog silence hunt must exclude low-volume standby HA peers"
    assert 'AuthenticationProtocol == "deviceCode"' in adj
    assert "isnull(RegTime)" in adj and "isempty(RegTime)" not in adj, "KQL datetime columns require isnull(), not isempty()"
    assert "/api/v1/totp/user-backup-code/" in adj
    assert "opt/panlogs/tmp/device_telemetry" in adj
    assert 'or RequestURL contains "/global-protect/portal/css/bootstrap.min.css"' not in adj, "Stock GlobalProtect CSS FPs if matched standalone"
    assert 'has ".."' not in adj and 'has ";"' not in adj, "KQL has/has_any cannot match pure punctuation"


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

    # Verify compiled packs preserve literal `?artex=` (not unescaped `?` wildcard) and CrowdStrike Linux basenames
    compiled_kql = (RULES_ROOT / "queries" / "compiled_sigma" / "compiled_kusto_generic.kql").read_text(encoding="utf-8")
    assert 'UrlOriginal contains "artex="' not in compiled_kql
    assert 'UrlOriginal contains "?artex="' in compiled_kql

    compiled_spl = (RULES_ROOT / "queries" / "compiled_sigma" / "compiled_splunk_spl.spl").read_text(encoding="utf-8")
    assert '"**artex=*"' not in compiled_spl

    compiled_cql = (RULES_ROOT / "queries" / "compiled_sigma" / "compiled_crowdstrike_logscale.cql").read_text(
        encoding="utf-8"
    )
    assert "/.artex=/i" not in compiled_cql
    assert r"/\?artex=/i" in compiled_cql
    assert r"ParentBaseFileName=/\/dpkg$/i" not in compiled_cql
    assert r"ParentBaseFileName=/\/pip$/i" not in compiled_cql
    assert "ParentBaseFileName=/^dpkg$/i" in compiled_cql
    assert "ParentBaseFileName=/^pip$/i" in compiled_cql


def test_ja4_agentic_patterns_json_schema_and_blocklist_safety_guard() -> None:
    """Ensure standalone JA4+ hunting guide, JSON reference, and DuckDB SQL query enforce FoxIO syntax & safety."""
    import json
    import duckdb

    guide = (REPO_ROOT / "docs" / "ja4_agentic_hunting_guide.md").read_text(encoding="utf-8")
    assert "DO NOT BLOCK ON STATIC JA4" in guide
    assert "e7c285222651" in guide and "ge11nn030000_cd680697de12_000000000000_000000000000" in guide
    assert ";\\\\s*wv\\\\)" in guide, "Splunk double-quoted regex must escape backslashes"

    jpath = RULES_ROOT / "intel_hunting" / "ja4_agentic_patterns.json"
    data = json.loads(jpath.read_text(encoding="utf-8"))
    assert "DO NOT BLOCK" in data["operational_warning"]
    refs = data["runtime_reference_fingerprints"]
    assert len(refs) == 21
    ja4_re = re.compile(r"^t\d{2}[di]\d{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$")
    ja4h_re = re.compile(r"^[a-z]{2}\d{2}[cn][rn]\d{2}[a-z0-9]{4}_[0-9a-f]{12}_[0-9a-f]{12}_[0-9a-f]{12}$")
    for item in refs:
        assert item["blocklist_safe"] is False, f"Static runtime fingerprint {item['id']} must set blocklist_safe=false"
        if item["fingerprint_type"] == "ja4":
            assert ja4_re.match(item["value"]), f"Invalid FoxIO JA4 format: {item['value']}"
        elif item["fingerprint_type"] == "ja4h":
            assert ja4h_re.match(item["value"]), f"Invalid FoxIO JA4H format: {item['value']}"
        else:
            raise AssertionError(f"Unexpected fingerprint_type: {item['fingerprint_type']}")
    patterns = data["structural_hunting_patterns"]
    assert len(patterns) >= 6
    for pat in patterns:
        for rx in pat.get("ja4_regex_any", []):
            re.compile(rx)
        for key in ("ja4_regex", "ja4h_regex"):
            if key in pat:
                re.compile(pat[key])

    # Execute Section 4.2 DuckDB SQL verbatim to verify Proxy-Collapse precedence, empty UA exclusion, and NULL http_path handling
    m_sql = re.search(r"```sql\n(.*?)\n```", guide, re.DOTALL)
    assert m_sql, "Expected SQL block in Section 4.2 of ja4_agentic_hunting_guide.md"
    con = duckdb.connect(":memory:")
    con.execute(
        "CREATE TABLE web_tls_telemetry (ts TIMESTAMP, source_host VARCHAR, dest_host VARCHAR, ja4 VARCHAR, ja4h VARCHAR, user_agent VARCHAR, status_code INTEGER, http_path VARCHAR)"
    )
    # 1. Proxy-ON case (1 JA4, 3 distinct JA4Hs, 3 UA families, 3x 404 with NULL path on one) -> MUST classify as JA4_PROXY_COLLAPSE
    con.executemany(
        "INSERT INTO web_tls_telemetry VALUES (NOW(), ?, ?, ?, ?, ?, ?, ?)",
        [
            ("10.0.0.10", "app.local", "t13d1311h2_f57a46bbacb6_e7c285222651", "ge11nn030000_fe444ad14866_000000000000_000000000000", "curl/8.5.0", 404, "/api/1"),
            ("10.0.0.10", "app.local", "t13d1311h2_f57a46bbacb6_e7c285222651", "ge11nn050000_be0d0b335e46_000000000000_000000000000", "python-httpx/0.28.1", 403, "/api/2"),
            ("10.0.0.10", "app.local", "t13d1311h2_f57a46bbacb6_e7c285222651", "ge11nn09enus_5e81b34521f1_000000000000_000000000000", "Mozilla/5.0 Chrome/131.0.0.0", 403, None),
            # 2. 2 UAs + 1 empty UA string -> must NOT count '' as a 3rd UA family!
            ("10.0.0.20", "app.local", "t13d1311h2_f57a46bbacb6_e7c285222651", "ge11nn030000_fe444ad14866_000000000000_000000000000", "curl/8.5.0", 404, "/a"),
            ("10.0.0.20", "app.local", "t13d1311h2_f57a46bbacb6_e7c285222651", "ge11nn050000_be0d0b335e46_000000000000_000000000000", "python-httpx/0.28.1", 404, "/b"),
            ("10.0.0.20", "app.local", "t13d1311h2_f57a46bbacb6_e7c285222651", "", "", 404, "/c"),
        ],
    )
    rows = con.execute(m_sql.group(1)).fetchall()
    assert len(rows) == 1 and rows[0][0] == "10.0.0.10" and "JA4_PROXY_COLLAPSE" in rows[0][-1], f"Unexpected SQL rows: {rows}"
