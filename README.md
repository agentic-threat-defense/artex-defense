# ARTEX Defensive Research & Threat-Hunting Workbench

> **WARNING — Operational Safety (Zero Bare-Metal Exposure):** Never browse, curl, download, or inspect raw attacker directories (`SimpleHTTP`), exposed operator consoles, or suspect C2 infrastructure from a bare-metal host or corporate workstation. Identify and triage exposed infrastructure strictly through passive intelligence platforms (e.g., **Censys**, **Shodan**, **Hunt.io**, **Google Threat Intelligence (GTI)**, **GreyNoise**, **Team Cymru**, **FOFA**, **Validin**, **Silent Push**, **URLScan.io**, or equivalent passive TI services). Any retrieved artifacts or `TaskID` transcripts must be inspected exclusively inside an isolated, snapshotted analysis VM (Tier 3 air-gapped KVM/QEMU) and sanitized/redacted prior to offline analysis (`./scripts/sandbox-scan.sh` / `./scripts/sandbox-analyze-tasks.sh`).

An open-source, local-first defensive detection-engineering and threat-hunting workbench designed to detect, triage, and defend against **ARTEX** (`Autumn-27/ARTEX`), its rapidly proliferating forks (**AntiFox**, **ScopeWeaver**, **Pojun**, **FORANG**, **ARTEX PRO**, **ARTEX MX**, **LUCK**, **Guanlan SEC**), and adjacent autonomous LLM-driven offensive frameworks (**HexStrike**, **CyberStrikeAI**, **PentAGI**, **Cairn**).

> **Production Tuning Note:** All detections, schemas, and thresholds are built strictly from public threat intelligence and synthetic/blind-tested baselines. Further testing, schema alignment, and threshold tuning will be required for live or custom production environments.

---

## Why Behavioral (Post-IOC) Detection?
Autonomous offensive agents compress multi-stage intrusions from days to **under 3 hours** while rotating residential proxy IPs, stripping User-Agents, renaming binaries, and fronting LLM traffic over standard TCP `443`. This workbench pairs **Tier A static forensic signatures** with **Tier B Zero-IOC behavioral detections** and **Risk-Based Alerting (RBA)** across six telemetry surfaces:

| Surface | High-Fidelity Static (Tier A) | Post-IOC Behavioral (Tier B) | Artifacts |
| :--- | :--- | :--- | :--- |
| **Edge Appliances** *(Cisco ASA/FTD, Citrix, PAN-OS, F5)* | VPN/gateway probing, `artex-enrich/1.0`, `norma/0.4`, self-proclaimed authorized UAs | Rapid & throttled VPN sprays, **distributed proxy-pool probing**, bimodal LLM Think-Act pauses | Sigma (#3–5, #10), Suricata, SIEM packs |
| **Web / API / WAF** | Unit 42 control-404 canaries, GreyNoise `artex=`, `alg:none` JWT spray, cloud metadata SSRF, `/uploads/` webshells | Error-correction pivots, **forced error-handling & random-slug soft-404 calibration**, spec-driven targeting, REST Write→Readback, **NAT-safe `JA4`/`JA4H` stack whiplash** | Sigma (#6, #10, #12), Zeek, Suricata, `detectors.py` |
| **Identity Providers (IdP / 2FA)** *(Okta, Entra ID, Duo, PingFederate, Google Workspace)* | Okta `deny_push`/`user.risk.detect`/Workflows; Entra `7000215`/`500121`; Duo `fraud_reported`/`bypass_create`; PingID rejections; GWS `2sv_disable`/`recovery_phone_edit` | **Spray-then-success**, **2FA push-bombing & rogue factor tampering**, **mass probe-account signups**, SP secret-guess→success, **SP multi-resource fan-out** | Native 5-IdP parsers, Sigma (#15–17), KQL & ES\|QL |
| **Cloud Control Plane** *(AWS & Azure)* | CloudWatch `FilterLogEvents` secret searches, EC2 `DryRunOperation`, Azure Kudu & `/deployments/validate`, AWS Cognito | **AntiFox multi-service AWS `AccessDenied` sweeps → `GetSecretValue`**, Entra SP fail→Key Vault/SAS pivot, multi-field IAM escalation | Sigma (#13), Elastic ES\|QL, MDE/Sentinel KQL |
| **Endpoints & Operator Hosts** *(Windows & Linux)* | `BLOODALCHEMY`, `/tasks/<id>/i<id>/cmd-output/`, `mitmproxy-ca-cert.pem` + `HTTP_PROXY`, `xcai-effort-shim.py`, Kerberoast/DCSync/`vshell`/`AdaptixC2`/`WISP` | Compressed recon bursts, **shell-wrapper-stripped multi-worker recon**, **LLM CLI context-budget idioms**, **touch-and-bail EDR evasion**, tightened web-parent shell spawns | Sigma (#1, #7, #8, #11, #14), YARA, `artex-hunt host-triage` |
| **Network & Encrypted Biflows** *(YAF IPFIX / RFC 5103, Zeek, JA4+)* | Console/proxy ports (`8787`/`8788`/`8790`/`8890`), `silkAppLabel`, self-signed `Issuer O=ARTEX` X.509 cert | **Compaction-resilient TLS 1.3 sawtooth growing-context LLM proxy**, raw-IP TLS (`t13i`/`t12i`), **`JA4X_c` + `JA4S`** clustering | Native YAF IPFIX parser, Zeek, Suricata, Spark SQL |

---

## Architecture

1. **Stage 1 — Deterministic Engine (`DuckDB` + Python, 0 LLM tokens):**
   Offline multi-format log parsers (`parsers.py`) + behavioral/artifact detectors (`detectors.py`) + `<3h` cross-surface kill-chain correlation + RBA scoring (`risk_score` 0–100).
2. **Stage 2 — Optional Local LLM Triage Worker (Ollama, offline/localhost-locked):**
   Triages only Stage 1 candidate windows into structured JSON verdicts, extracts defensive intel from local advisories, and drafts starter Sigma/YARA/KQL/Zeek rules (`worker.py`, `models/Modelfile.gemma4-hunter`).
3. **Stage 3 — Optional Stdio MCP Boundary (`artex-mcp`):**
   Exposes deterministic scanning and local LLM delegation over MCP with automatic secret/email redaction, IP pseudonymization, and URL/domain defanging (`sanitize=True` by default).
4. **Tier 2 & Tier 3 Quarantine Infrastructure:**
   - Offline Docker wrappers (`scripts/sandbox-scan.sh`, `scripts/sandbox-analyze-tasks.sh`) running with `--network=none --read-only --cap-drop=ALL`.
   - Air-gapped KVM/QEMU sensor + target lab IaC (`lab/kvm/`).

---

## Quick Start

```bash
# Install with dev & Sigma compiler extras
python3 -m venv .venv
.venv/bin/pip install -e ".[dev,sigma]"

# Run the offline unit, adversarial, IdP, IPFIX, Sigma & KVM lab test suite (40 tests)
.venv/bin/pytest -v -m "not live"

# Run the 28-dataset multi-surface Precision/Recall evaluation harness
.venv/bin/artex-hunt eval

# Validate & compile all 19 Sigma rules across 7 SIEM/XDR formats
.venv/bin/artex-hunt sigma-compile --export-dir rules/queries/compiled_sigma

# Stage 1 deterministic scan (zero LLM calls, optional authorized scanner CIDR allowlist)
.venv/bin/artex-hunt scan tests/fixtures/sample_telemetry.jsonl --scanner-ip 10.50.0.0/24

# Strictly read-only operator/relay host forensic triage
.venv/bin/artex-hunt host-triage

# Hardened offline Docker container scan & TaskID transcript analysis (--network=none)
./scripts/sandbox-scan.sh quarantine/raw_logs.jsonl quarantine/sanitized_candidates.json
./scripts/sandbox-analyze-tasks.sh quarantine/task_transcripts/ quarantine/sanitized_tasks.json

# Scheduled / on-demand defensive Threat-Intel Watchtower (allowlisted feeds + SQLite dedup + optional local GPU gap digest)
.venv/bin/artex-hunt watchtower --with-gemma4
```

---

## Key Documentation & Rule Packs

- **Framework Delivery Overview:** [docs/FIRST_DRAFT_DELIVERY.md](docs/FIRST_DRAFT_DELIVERY.md)
- **References, Acknowledgments & Further Research:** [docs/REFERENCES_AND_ACKNOWLEDGMENTS.md](docs/REFERENCES_AND_ACKNOWLEDGMENTS.md)
- **SOC Shadow-Mode SIEM Validation Playbook:** [docs/soc_siem_validation_playbook.md](docs/soc_siem_validation_playbook.md)
- **Production Schema Adaptation Pack (YAF IPFIX + JA4X + Spark SQL):** [docs/production_adaptation_pack.md](docs/production_adaptation_pack.md)
- **Blind Out-of-Distribution Stress-Test Log:** [docs/blind_stress_test_log.md](docs/blind_stress_test_log.md)
- **Quarantine & OpSec SOP:** [docs/quarantine_sop.md](docs/quarantine_sop.md)
- **Threat Model & Hardening Guide:** [docs/artex_threat_model.md](docs/artex_threat_model.md), [docs/edge_to_endpoint_hardening.md](docs/edge_to_endpoint_hardening.md)
- **SIEM / EDR Query Packs:** `rules/queries/` & `rules/queries/compiled_sigma/` (Elastic ES|QL/EQL/Lucene, Microsoft MDE/Sentinel KQL, CrowdStrike LogScale CQL, SentinelOne S1QL, Splunk SPL)
- **Network & Binary Rules:** `rules/sigma/` (19 rules), `rules/network/` (Suricata + Zeek), `rules/yara/` (Livehunt & Retrohunt), `rules/intel_hunting/` (passive TI query templates)
- **Air-Gapped Sensor Lab IaC:** [lab/kvm/README.md](lab/kvm/README.md)

---

## Primary Sources & Independent Research

This workbench is **not** intended to be treated as standalone ground truth. It builds upon pioneering public reporting and open-source defensive repositories from **ThreatDefence** (`ThreatDefence/artex-detections`), **Theori** (`theori-io/aipt-detections`), **ARTEX Global contributors** (`jiwoochris/artex-global`), **Will Thomas (`@BushidoToken`)**, **Palo Alto Networks Unit 42**, **Hunt.io**, **Arctic Wolf**, **CrowdStrike**, **Microsoft Threat Intelligence**, **Google Threat Intelligence Group (GTIG)**, **Cisco Talos**, **GreyNoise**, **Censys**, **SigmaHQ / pySigma**, **FoxIO (JA4+)**, and **CERT NetSA (YAF / IPFIX)**.

Please see [docs/REFERENCES_AND_ACKNOWLEDGMENTS.md](docs/REFERENCES_AND_ACKNOWLEDGMENTS.md) for direct links and guidance on conducting independent verification and follow-on research.

---

## License & Defensive Scope

Licensed under the [Apache License 2.0](LICENSE). See [SECURITY.md](SECURITY.md) for strict defensive-use scope and responsible disclosure guidance.
