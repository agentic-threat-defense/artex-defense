# artex-defense

[![CI](https://github.com/agentic-threat-defense/artex-defense/actions/workflows/ci.yml/badge.svg)](https://github.com/agentic-threat-defense/artex-defense/actions/workflows/ci.yml)

Offline detection engineering, log triage, and hunting rules for **ARTEX** (`Autumn-27/ARTEX`), its active forks (AntiFox, ScopeWeaver, Pojun, FORANG, Guanlan SEC), and adjacent autonomous LLM-driven offensive tools (CyberStrikeAI, HexStrike, PentAGI, Cairn, Hermes Agent).

Static strings from early advisories (`ArtexProbe`, realm headers, canary paths) are useful for retrohunting and passive infrastructure pivoting, but forks strip them within days. This repository pairs static retrohunt indicators with **Zero-IOC behavioral detections**—timing cadence, error-handling calibration, TLS/JA4 stack whiplash and recording-proxy TLS collapse, sub-3-hour kill-chain compression, and 30-day dormant-gap correlation—scored via Risk-Based Alerting (`risk_score` 0–100).

*Scope note: This repository is an **offline detection-engineering workbench and single-case triage kit**. In live SOC environments, deploy the compiled SIEM/XDR/network rules with per-entity rolling baselines rather than piping production firehoses through a standalone CLI/LLM. All detectors, schemas, and thresholds are derived from public reporting and synthetic/blind-tested baselines; live schema alignment and threshold tuning will be required.*

> [!WARNING]
> **Operational Safety (Zero Bare-Metal Exposure):** Never browse, curl, or pull raw attacker directories (`SimpleHTTP`), exposed operator consoles, or suspect C2 infrastructure from a bare-metal workstation. Use passive intelligence platforms (Censys, Shodan, Hunt.io, GTI, GreyNoise, URLScan.io, Silent Push, Validin, Team Cymru, FOFA) to triage infrastructure, inspect artifacts only inside an isolated snapshotted VM, and sanitize untrusted logs offline via `./scripts/sandbox-scan.sh`. See [docs/quarantine_sop.md](docs/quarantine_sop.md).

---

## Start Where You Need

- **Detection Engineers:** 21 validated Sigma rules in [rules/sigma/](rules/sigma/), pre-compiled SIEM/XDR packs in [rules/queries/compiled_sigma/](rules/queries/compiled_sigma/) (Elastic ES|QL & Lucene, Microsoft KQL/MDE/Sentinel ASIM, CrowdStrike LogScale CQL, Splunk SPL, SentinelOne S1QL), Zeek/Suricata in [rules/network/](rules/network/), YARA in [rules/yara/](rules/yara/), and Tenable One / Nessus `.audit` + ASM/Cloud/Identity packs in [rules/tenable/](rules/tenable/).
- **Incident Responders:** Read-only Linux/offline-image operator host triage (`artex-hunt host-triage`) and `--network=none --read-only` Docker log/transcript wrappers ([scripts/sandbox-scan.sh](scripts/sandbox-scan.sh), [scripts/sandbox-analyze-tasks.sh](scripts/sandbox-analyze-tasks.sh)).
- **Tabletop & Purple Teams:** Follow the [Live-Lab & Purple-Team Evaluation Guide](docs/LAB_EVALUATION_GUIDE.md) to test against an isolated lab range, or run `artex-hunt simulate` / `artex-hunt eval` for 42 self-contained synthetic datasets (22 multi-surface agentic scenarios + 20 benign baselines).
- **Threat Hunters & Researchers:** Standalone JA4+ agentic hunting guide ([docs/ja4_agentic_hunting_guide.md](docs/ja4_agentic_hunting_guide.md) & [ja4_agentic_patterns.json](rules/intel_hunting/ja4_agentic_patterns.json)), blind out-of-distribution stress-test logs ([docs/blind_stress_test_log.md](docs/blind_stress_test_log.md)), threat model ([docs/artex_threat_model.md](docs/artex_threat_model.md)), and primary-source references ([docs/REFERENCES_AND_ACKNOWLEDGMENTS.md](docs/REFERENCES_AND_ACKNOWLEDGMENTS.md)).

---

## Detection Coverage

| Surface | Behavioral (Zero-IOC) Signals | Static / Forensic Signals | Rules & Parsers |
| :--- | :--- | :--- | :--- |
| **Edge Appliances** *(ASA/FTD, Citrix, PAN-OS, F5)* | Rapid & throttled VPN sprays, distributed proxy-pool probing, bimodal LLM think-act pauses | Gateway path probes, `artex-enrich/1.0`, `norma/0.4`, self-proclaimed authorized UAs | Native parsers, Sigma, Suricata |
| **Web / API / WAF** | Error-correction pivots, forced error-class & random-slug 404 calibration, Zero-IOC `500/502` heap-grooming crash loops (`web_memory_corruption_crash_loop`), OpenAPI spec targeting, REST write-then-readback, NAT-safe JA4/JA4H stack whiplash, time-independent browser-UA stack impersonation (`browser_ua_stack_impersonation`), single-JA4 recording-proxy collapse (`ja4_proxy_collapse_multi_ua`), cross-direction server callback on probe, operator-configurable honey-route/token canaries (`--canary-path`/`--canary-token`) | Control-404 canaries, Ruby2Shell (`CVE-2026-132825` `sid:9100021`), `alg:none` JWT spray, cloud metadata SSRF, SAPControl SOAP (`OSExecute`/config reads), `.htaccess` PHP upload reactivation, CMS/upload webshell bypasses, GraphQL introspection & AI/MCP path discovery | `detectors.py`, Sigma, Zeek, Suricata |
| **Identity Providers** *(Okta, Entra ID, Duo, PingFederate, Google Workspace)* | Spray-then-success, 2FA push fatigue & factor tampering, mass self-service probe signups, federated multi-`client_id`/cross-RP trust probing, SP secret-guess-then-success, multi-resource fanout, & zero-`401` pre-authorized SP multi-IP replay (`idp_sp_multi_ip_replay`) | Okta `user.risk.detect` & Workflows invoke abuse, Entra `7000215`/`500121`, Duo `fraud_reported`, PingID rejections, GWS `2sv_disable` | Native 5-IdP parsers, Sigma, KQL & ES\|QL |
| **Cloud Control Plane** *(AWS, Azure, & GCP)* | Multi-service `AccessDenied` / GCP `PERMISSION_DENIED` sweeps to `GetSecretValue` / `AccessSecretVersion`, 100%-`200 OK` stolen-key multi-service enum, sub-2s cloud bursts (EC2 `userData` / SSM), external EC2 instance-role replay, single-IP multi-identity pivoting (AWS IAM/roles, Azure SPs, & GCP `*.gserviceaccount.com`), 30-day dormant-gap shared-IP correlation | Native AWS CloudTrail & GCP Cloud Audit JSON parsers, CloudWatch `FilterLogEvents` secret queries, EC2 `DryRunOperation`, GCP `CreateServiceAccountKey` / `GenerateAccessToken` / `SetIamPolicy`, Azure Kudu & `/deployments/validate`, LLM API key harvesting | `parsers.py`, `detectors.py`, Sigma, ES\|QL, KQL |
| **Endpoints & Operator Hosts** *(Windows & Linux)* | Compressed & compound shell recon bursts, wrapper-stripped multi-worker redundant recon (with Debian/Ubuntu `pam_motd` hygiene), Ruby/Puma/Unicorn/Passenger & web-parent shell spawns, LLM CLI context-budget idioms, touch-and-bail EDR sweeps, SMB/WinRM lateral fanout, on-box staging compilation | `/tasks/<id>/i<id>/cmd-output/`, `mitmproxy-ca-cert.pem` + `HTTP_PROXY`, `xcai-effort-shim.py`, `BLOODALCHEMY` & signer-scoped DLL sideloading, K8s privileged pod staging & SA token theft, `systemd` & ephemeral server tunnels (`cloudflared tunnel --url`, `devtunnel host`), NTLM relay (`Responder/Responder.py`, `Coercer`)/LDAP-Kerb enum, Chisel/Ligolo/Proxychains pivots | Sigma, YARA, `artex-hunt host-triage` |
| **Encrypted Network & Biflows** *(YAF IPFIX / RFC 5103, Zeek, PCAP JA4/JA4H)* | Compaction- & `NewSessionTicket`-resilient TLS 1.3 sawtooth & persistent-socket turn loops, cross-channel `TLS_IN → Action → TLS_OUT` causal coupling (`causal_tls_action_loop`, beats `>10 s` jitter & 60 s windows), wire FoxIO JA4/JA4H PCAP extraction, raw-IP TLS (`t13i`/`t12i`), custom-domain high-entropy DNS OOB callbacks, `JA4X_c` + `JA4S` clustering | Default console/proxy ports (`8787`/`8788`/`8790`/`8890`/`18899`), self-signed `Issuer O=ARTEX` certs, server-only bot C2 egress | Native YAF/IPFIX parser, Zeek, Suricata |

---

## Quick Start

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev,sigma]"

# Run the offline test suite (parsers, Zero-IOC evasion, IdPs, IPFIX, security hardening, Sigma, KVM lab)
.venv/bin/pytest -v -m "not live"

# Run the 42-dataset Precision/Recall evaluation harness
.venv/bin/artex-hunt eval

# Stage 1 deterministic scan (0 LLM tokens; optional allowlists & deception canaries)
.venv/bin/artex-hunt scan tests/fixtures/sample_telemetry.jsonl --scanner-ip 10.50.0.0/24 --trusted-proxy-ip 10.20.0.0/24 --canary-path /api/v1/internal/credential-export

# Strictly read-only host triage (live /proc & paths, or --root for a mounted forensic image)
.venv/bin/artex-hunt host-triage
```

---

<details>
<summary><strong>Architecture & Optional Components</strong> (Stage 1 DuckDB -> Local Ollama -> Hardened MCP)</summary>

1. **Stage 1 — Deterministic Engine (`DuckDB` + Python, 0 LLM tokens):**
   Offline multi-format log parsers (`parsers.py`), behavioral and artifact detectors (`detectors.py`), sub-3-hour and 30-day kill-chain correlation (`correlate_kill_chains`), and Risk-Based Alerting (`risk_score` 0–100; `alert >= 70`, `hunt >= 45`).
2. **Stage 2 — Optional Local LLM Triage Worker (`worker.py`):**
   Connects strictly to a localhost Ollama instance (`models/Modelfile.gemma4-hunter`) to triage only Stage 1 candidate windows into schema-validated JSON verdicts or draft starter rules. Prompt-injection fencing wraps all untrusted telemetry.
3. **Stage 3 — Hardened Stdio MCP Server (`artex-mcp`):**
   Exposes deterministic scanning and local LLM delegation over stdio MCP with workspace path jailing (`ARTEX_MCP_ALLOWED_ROOT`), sensitive-file blocking, file-size limits, and mandatory redaction/defanging by default.

</details>

<details>
<summary><strong>Offline Docker Sandbox, Isolated Validation Ranges & Watchtower</strong></summary>

```bash
# Re-compile Sigma rules across 8 SIEM/XDR target packs (full-pack ES|QL/Lucene/KQL/CQL/SPL + Windows-endpoint MDE/ASIM/S1QL)
.venv/bin/artex-hunt sigma-compile --export-dir rules/queries/compiled_sigma

# Offline Docker container scan & TaskID transcript analysis (--network=none, --read-only, --cap-drop=ALL)
./scripts/sandbox-scan.sh quarantine/raw_logs.jsonl quarantine/out/sanitized_candidates.json
./scripts/sandbox-analyze-tasks.sh quarantine/task_transcripts/ quarantine/out/sanitized_tasks.json

# Allowlisted public threat-intel Watchtower (HTTPS allowlist + SQLite dedup + optional local LLM gap digest)
.venv/bin/artex-hunt watchtower --with-gemma4

# Non-routed isolated Docker purple-team range (real Suricata 7, Zeek LTS, YARA, Nginx + automated assertions)
bash lab/docker-range/run-range.sh

# Host-only isolated KVM/QEMU sensor + target lab (zero <forward> network invariant, real Linux auditd)
./lab/kvm/lab-ctl.sh check
```

</details>

<details>
<summary><strong>Documentation Index</strong></summary>

- [docs/LAB_EVALUATION_GUIDE.md](docs/LAB_EVALUATION_GUIDE.md) — Quick clone, drop-in SIEM/NSM packs, and highest-value telemetry for live-lab / purple-team evaluation
- [docs/FIRST_DRAFT_DELIVERY.md](docs/FIRST_DRAFT_DELIVERY.md) — Full component overview and verification matrix
- [docs/REFERENCES_AND_ACKNOWLEDGMENTS.md](docs/REFERENCES_AND_ACKNOWLEDGMENTS.md) — Upstream researchers, repositories, and advisories
- [docs/soc_siem_validation_playbook.md](docs/soc_siem_validation_playbook.md) — Positive-control schema checks and 7-day shadow-mode tuning
- [docs/production_adaptation_pack.md](docs/production_adaptation_pack.md) — YAF IPFIX, JA4X/JA4S, and Spark SQL query templates
- [docs/ja4_agentic_hunting_guide.md](docs/ja4_agentic_hunting_guide.md) — Standalone FoxIO JA4/JA4H/JA4X hunting guide, live-measured Go 1.22–1.24 / Python / `curl` reference tables, and anti-blocklist caveats ([rules/intel_hunting/ja4_agentic_patterns.json](rules/intel_hunting/ja4_agentic_patterns.json))
- [docs/blind_stress_test_log.md](docs/blind_stress_test_log.md) — Multi-round blind out-of-distribution stress-test findings
- [docs/ADVERSARIAL_REVIEW_BOARD.md](docs/ADVERSARIAL_REVIEW_BOARD.md) — 5-seat fresh-context Adversarial Review Board & CTO release-gate methodology
- [docs/artex_threat_model.md](docs/artex_threat_model.md) & [docs/edge_to_endpoint_hardening.md](docs/edge_to_endpoint_hardening.md) — Threat model and hardening controls
- [docs/quarantine_sop.md](docs/quarantine_sop.md) — Tier 1–3 quarantine handling and artifact OpSec
- [docs/ROADMAP.md](docs/ROADMAP.md) — Known limitations and open engineering work
- [lab/docker-range/README.md](lab/docker-range/README.md) — Non-routed isolated Docker validation range (real Suricata 7, Zeek LTS, YARA, Nginx)
- [lab/kvm/README.md](lab/kvm/README.md) — Reproducible host-only isolated KVM/QEMU Zeek & Linux Auditd lab setup
- [rules/intel_hunting/adjacent_china_nexus_edge_and_idp_hunts.md](rules/intel_hunting/adjacent_china_nexus_edge_and_idp_hunts.md) — Companion hunting templates for overlapping China-nexus edge/router/IdP campaigns (Storm-0940, Crystal Typhoon, Salt Typhoon)

</details>

---

## Primary Sources & Attribution

This workbench is a community synthesis, not standalone ground truth. It builds on primary research and open-source rule packs from **ThreatDefence** (`ThreatDefence/agentic-attack-detections`), **Theori / Xint** (`theori-io/aipt-detections`), **Athar** (`Athar-HQ/Athar`, Florian Roth & Gameel Ali, DRL 1.1), **MalwareMustDie** (`MMD-072-2026`), **ARTEX Global & community kit maintainers** (`jiwoochris/artex-global`, `logsexe`, `ja1sh`, `Kshot3000`), **Andrea Palmieri** (`andpalmier`), **Will Thomas** (`@BushidoToken`), **FBI / IC3** (`FLASH-20261113-001`), **Unit 42**, **Okta Threat Intelligence**, **Elastic Security Labs**, **Amazon MadPot**, **Hunt.io**, **Arctic Wolf**, **CrowdStrike**, **Microsoft Threat Intelligence**, **GTIG / Mandiant**, **Cisco Talos**, **GreyNoise**, **SigmaHQ / pySigma**, **FoxIO (JA4+)**, and **CERT NetSA (YAF / IPFIX)**.

See [docs/REFERENCES_AND_ACKNOWLEDGMENTS.md](docs/REFERENCES_AND_ACKNOWLEDGMENTS.md) for direct links and notes on where detections here extend upstream findings.

## License & Security

Licensed under the [Apache License 2.0](LICENSE). For strict defensive-use boundaries and private vulnerability reporting, see [SECURITY.md](SECURITY.md).
