# ARTEX Defensive Research Workbench — Public Roadmap

## Completed Capabilities
- **Multi-Surface Deterministic Engine & RBA Scoring (`src/artex_defense/detectors.py`):**
  - Edge appliances (Cisco ASA/FTD, Citrix NetScaler, PAN-OS, F5 BIG-IP), Web/API/WAF, Identity Providers (Okta System Log, Microsoft Entra ID, Duo Security, PingFederate, and Google Workspace), Cloud IAM (AWS & Azure), Endpoints (Windows & Linux), and Network/Encrypted Biflows (Zeek, Suricata, CERT NetSA YAF / `super_mediator` RFC 5103 IPFIX).
  - Risk-Based Alerting (`risk_score` 0–100; `alert` / `hunt` / `info` tiers) + IP/CIDR authorized scanner allowlisting (`--scanner-ip`).
- **Zero-IOC / Post-IOC Behavioral Detections:**
  - Compaction-resilient encrypted TLS 1.3 sawtooth growing-context LLM proxy detection (`llm_sawtooth_context_flow`).
  - Forced error-handling & random-slug 404 calibration (`web_error_handling_calibration`).
  - NAT-safe `JA4`/`JA4H` client-stack whiplash (`ja4_client_stack_whiplash`) paired with single-JA4 recording-proxy TLS collapse (`ja4_proxy_collapse_multi_ua`).
  - Shell-wrapper-stripped redundant multi-worker recon (`multi_worker_redundant_recon`), LLM CLI context-budget idioms (`llm_cli_context_idioms`), touch-and-bail EDR evasion (`touch_and_bail_edr_evasion`), distributed proxy-pool probing (`distributed_proxy_pool_probe`), native AWS CloudTrail CyberStrikeAI/AntiFox detections, and bipartite entity-linked short & rolling 30-day kill-chain correlation.
- **Automated Multi-Backend Sigma Compilation (`artex-hunt sigma-compile`):**
  - 19 Sigma rules validated with 0 schema errors and compiled across 8 SIEM/XDR target packs (full-pack Elastic ES|QL & Lucene, generic Microsoft KQL, CrowdStrike LogScale CQL, Splunk SPL; plus Windows-endpoint-scoped MDE XDR, Sentinel ASIM, and SentinelOne S1QL).
- **Defense-in-Depth Quarantine Tooling:**
  - Offline `--network=none --read-only --cap-drop=ALL` Docker wrappers (`scripts/sandbox-scan.sh`, `scripts/sandbox-analyze-tasks.sh`).
  - Read-only operator/relay host forensic triage (`artex-hunt host-triage`).
  - Reproducible air-gapped KVM/QEMU sensor + target lab IaC (`lab/kvm/`).
- **Scheduled Defensive Threat-Intel Watchtower (`artex-hunt watchtower` + `scripts/systemd/`):**
  - 47 live-verified allowlisted HTTPS public defensive feeds (international CERTs, cloud/IdP TI, defensive repos, and categorized GitHub `releases.atom` tracking), SQLite deduplication (`quarantine/watchtower/state.sqlite`), streaming XML size & prolog DTD guards, optional local Ollama GPU gap analysis, and `systemd` 6-hour user timer templates.
- **Validation & Adversarial Hardening:**
  - 60+ automated tests (including adversarial security hardening, native CloudTrail/IdP/IPFIX parsers, and Zero-IOC regressions), 34-dataset synthetic precision/recall harness, and three rounds of blind stress testing (`docs/blind_stress_test_log.md`).

---

## Ongoing & Planned Work
- [ ] **Real Uncurated Background-Noise Benchmarking:** Run Stage 1 detectors against real messy public enterprise/lab captures (e.g., Splunk BOTS, CIC-IDS, uncurated Zeek/HTTP background traffic) to measure empirical false-positive rates per 100k events outside synthetic fixtures.
- [ ] **Per-Entity Rolling SIEM Baselines:** Translate stateless global Stage 1 thresholds (e.g., cloud API fanout, AWS NAT Gateway egress CIDRs, per-user SSO baselines) into 30-day rolling peer-group anomaly queries for Elastic/Sentinel/Splunk.
- [ ] **Air-Gapped KVM Sensor Replay Packs:** Add additional benign enterprise traffic profiles (CI runners, SPA web apps, IT inventory automation) for `lab/kvm/benign_replay.py` to test Zeek/Auditd false-positive rates on real VM captures.
- [ ] **Ongoing Passive Threat-Intel Hygiene (Operational Workflow):**
  1. Identify exposed consoles and staging directories strictly through passive intelligence platforms (e.g., Censys, Shodan, Hunt.io, GTI, GreyNoise, Team Cymru, FOFA, Validin, Silent Push, URLScan.io, or equivalent passive TI services).
  2. Never browse, download, or inspect raw attacker directories from a bare-metal host; use an isolated, snapshotted Tier 3 air-gapped VM for any artifact inspection.
  3. Sanitize and redact any collected `TaskID` transcripts via `./scripts/sandbox-analyze-tasks.sh` before offline rule-tuning analysis.
