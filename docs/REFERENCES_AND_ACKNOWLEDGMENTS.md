# References, Acknowledgments & Further Research

> **Important — Do Not Treat This Repository as Ground Truth:**
> Autonomous offensive frameworks (**ARTEX**, **AntiFox**, **ScopeWeaver**, and emerging forks) evolve rapidly, and static indicators decay within hours. This workbench is a **community synthesis and engineering starting point**, not an authoritative or exhaustive source of truth.
>
> Always consult the primary research, upstream open-source detection repositories, telemetry specifications, and your own live environment baselines before drawing conclusions or deploying production detections.

---

## 1. Open-Source Defensive Repositories & Independent Researchers

This project builds on and cross-references pioneering open-source defensive work published by the security community. Readers are strongly encouraged to follow and pull directly from these upstream projects:

| Project / Researcher | Primary Focus & Contributions | Reference |
| :--- | :--- | :--- |
| **ThreatDefence** (`agentic-attack-detections` / formerly `artex-detections`) | Open-source multi-framework IOC CSVs, Sigma/KQL/Zeek/Suricata/YARA packs covering ARTEX, AntiFox, Cairn, Strix, PentAGI, HexStrike, CyberStrikeAI, Hermes Agent, Agent Zero, and Storm-3358 | `https://github.com/ThreatDefence/agentic-attack-detections`<br>`https://threatdefence.com/article/artex-agentic-attack-framework-detection-hunting` |
| **ARTEX Detection Resources Directory** | Curated master catalog of vendor advisories, forensic breakdowns, and community defensive repositories | `https://www.artex.sh/guides/artex-detection-resources` |
| **MalwareMustDie (`MMD-072-2026`)** | Multi-format ARTEX defense pack (STIX, Osquery, Sigma, KQL, Snort, Suricata, YARA) and hunting playbook | `https://github.com/MalwareMustDie` |
| **Theori / Xint** (`aipt-detections`) | Detection engineering for autonomous pentesting tools, ARTEX Exploration Graph & worker spill paths (`/tasks/<id>/i<id>/cmd-output/`), `mitmproxy-ca-cert.pem` + `HTTP_PROXY` injection, console routes, tarpit/credential hardening | `https://github.com/theori-io/aipt-detections` |
| **Athar** (`Athar-HQ/Athar` — Florian Roth `@cyb3rops` & Gameel Ali `@MalGamy12`, [DRL 1.1](https://github.com/SigmaHQ/Detection-Rule-License)) | Portable Sigma-style YAML service-fingerprinting standard & multi-engine query converter (FOFA/Shodan/Censys/ZoomEye/Modat/urlscan.io) for agentic offensive frameworks (ARTEX + Korean/English console titles, favicon `-576220750`, AntiFox `antifox.*.nip.io`, Next.js stylesheet hashes for title-stripped rebrands, Cairn, CyberStrikeAI, PentAGI, RedAmon, Strix, AutoCVE, DeepAudit) | `https://github.com/Athar-HQ/Athar` |
| **ARTEX Global & Community Defense Kits** | `jiwoochris/artex-global` (`artex_host_triage.py`), `logsexe/artex-detection-as-code`, `ja1sh/artex-defense`, and `Kshot3000/artex-defense-kit` (User-Agents including `Rex_Enrich`/`Norma`, console `:8787`, SIEM packs) | `https://github.com/jiwoochris/artex-global`<br>`https://github.com/logsexe/artex-detection-as-code`<br>`https://github.com/ja1sh/artex-defense`<br>`https://github.com/Kshot3000/artex-defense-kit` |
| **ProjectDiscovery Nuclei Templates** | Open-source scanning templates for identifying exposed ARTEX web consoles (PR `#17880`) | `https://github.com/projectdiscovery/nuclei-templates/pull/17880` |
| **Will Thomas (`@BushidoToken`)** | Public OSINT reporting on LLM-invented self-proclaimed "authorized" scanner User-Agents (`LLMLeak-RedTeam/1.0`, `authorized-security-research/1.0`, `authorized-exposure-audit/6`) | `https://x.com/BushidoToken` |
| **Andrea Palmieri (`andpalmier`)** | *"ARTEX: reading the source behind the IOCs"* (Nov 2026) — Source-code, git-history, and 73-fork audit of 62 published indicators across 11 advisories showing most target-side strings (`ArtexProbe`, `zz_no_such_user`, realm headers) are LLM-improvised or stripped by forks within days, and that "idle-then-burst" pauses reflect LLM reasoning latency. **Key detection difference incorporated here:** Palmieri's lab test showed ARTEX's optional traffic-recording proxy collapses underlying tool TLS handshakes (`curl`, `python`, browser) into a single Go TLS stack — the exact inverse of unproxied multi-tool `ja4_client_stack_whiplash` (`>=3` distinct `ja4`s). To cover both operating modes, this workbench pairs `ja4_client_stack_whiplash` (proxy off) with `ja4_proxy_collapse_multi_ua` (proxy on: `1` constant `ja4` + `>=3` distinct client UA families during non-asset/edge probing, with corporate-SWG browser-version guards). | `https://andpalmier.com/` |
| **Risky Business** | Investigative reporting and community discussion on autonomous offensive agent proliferation and forks | `https://risky.biz/RBFEATURES45/` |

---

## 2. Public Threat Intelligence Advisories & Vendor Research

Behavioral hypotheses, kill-chain timelines, and forensic artifacts in this workbench synthesize public reporting from the following threat-intelligence teams — please read their full primary publications for complete campaign context and updated indicators:

- **Palo Alto Networks Unit 42** — Foundational ARTEX campaign analysis: control-404 canaries (`zz_no_such_user`, `zzzrandom`), OpenAPI/source-map targeting, `Sub2API` (`:8080`) overlap, `lanmao666[.]com`, OAuth `illegal_redirect_uri_enhanced`, and compressed intrusion timelines.
- **Hunt.io** — Infrastructure deep dive on South Korean banking campaign operations (`hunt.io/blog/artex-south-korea-bank-infrastructure`): 10-year self-signed `Issuer O=ARTEX` X.509 certificate pivoting, `xcai-effort-shim.py` / `xcai[.]pro` LLM routing, and UnboundID JNDI/LDAP staging servers.
- **Arctic Wolf** — **AntiFox** (`AntiFox-AI/antifox`) intrusion reporting: IIS `w3wp.exe` → ASPX webshell → `web.config` harvesting → machine-speed `Boto3` AWS/Bedrock `AccessDenied` sweeps pivoting to `GetSecretValue`.
- **Amazon Security / MadPot** — Decoy telemetry exposing ARTEX self-funding AI model API-key harvesting (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, AWS Bedrock) and **Cairn** autonomous exploitation loops.
- **Okta Threat Intelligence** — Oct/Nov 2026 autonomous identity-reconnaissance advisories covering 390+ hour **ARTEX**/**Cairn** Okta/Auth0 probing, mass self-service probe account registrations (`user.lifecycle.create`), `user.risk.detect`, Okta Workflows invoke-URL abuse, and MCP-driven OpenBullet 2.
- **Cloudflare Security** — Internet-scale telemetry documenting 30x volumetric spikes in LLM-orchestrated scanning and exploitation loops.
- **CrowdStrike** — **VAPOR PANDA** (`BLOODALCHEMY` backdoor, automated EDR sensor discovery/bypass, and open staging directory analysis).
- **Microsoft Threat Intelligence** — *What defenders need to know about ARTEX* (`2026-11-25`, `https://www.microsoft.com/en-us/security/blog/2026/11/25/what-defenders-need-to-know-artex-agentic-ai-framework-threat-actors-abuse/`): confirms ARTEX adoption across **Storm-0940** (zero-interactive-sign-in multi-tenant Service Principal / Graph API abuse, ConnectWise Cloud Backup), **Storm-3358** (web-app SSRF/upload → webshell → RAT staging), **Onyx Sleet**, **Pearl Sleet**, **Crystal Typhoon**, and **Salt Typhoon**, `< 5 min` GitHub-secret-to-Azure-Key-Vault exfiltration, and behavioral velocity as the primary durable signal.
- **Google Threat Intelligence Group (GTIG) / Mandiant** — Tracking of ARTEX, `ArtexProbe`, and sub-3-hour autonomous intrusion compression.
- **Cisco Talos** — Official Snort 2 (`1:67494–1:67496`) and Snort 3 (`7:76–7:78`) IPS signatures covering ARTEX and the `norma` SDK harness.
- **GreyNoise** — Internet-wide scanner tracking and tags (`ARTEX-Enrichment User-Agent (Possible ARTEX)`, `ARTEX Parameter Attempt (Possible ARTEX)`).
- **FBI / IC3 (`FLASH-20261113-001`)** — *Threat Overview of ARTEX Autonomous Penetration Testing Framework* (`https://www.ic3.gov/CSA/2026/261113.pdf`), providing official indicator tables, MITRE ATT&CK mappings, sub-3-hour intrusion compression warnings, and baseline mitigations.
- **Datadog Security Labs, ExtraHop, SOC Prime & Blackfish Security** — Cloud/identity & self-hosted AI gateway hunting queries (Datadog), idle-then-burst network telemetry patterns (ExtraHop), Sigma/campaign aggregation for Storm-0940 & Storm-3358 (SOC Prime), and ARTEX Forensics warnings on pre-login root backdoors in community Docker images (Blackfish Security).
- **Elastic Security Labs** — Agentic offensive framework detections and the CyberStrikeAI CloudTrail deep dive (*"56 AWS API calls in 141 milliseconds"*: bulk EC2 `userData` extraction, SSM decryption/`SendCommand`, multi-identity single-IP pivoting, and 14-day dormant-gap evasion; `elastic.co/security-labs/threat-command/cyberstrikeai-aws-cloudtrail-intrusion`).
- **Wiz Research** — *Inside Agentic Offensive Frameworks: Intent IDs* (`2026-11-25`, Rami McCarthy & Hila Ramati, `https://www.wiz.io/blog/agentic-offensive-frameworks-intent-ids-artex-cairn`): breaks down how sequential `iNNNN` Intent IDs leak into victim logs, contrasting ARTEX's monotonic cross-target counter (enabling cross-IP pacing & attribution) against Cairn's per-project reset to `i001`.
- **Censys, ReversingLabs, GitGuardian, Prophet Security, Brandefense & BadByte** — Internet-exposed console & open Python `SimpleHTTP` tracking, fork taxonomy (`ScopeWeaver`, `Pojun`, `FORANG`, `ARTEX MX`, `Guanlan SEC`, `sco-fix2`), trojanized Docker image warnings (`tomicdd/artex`, `congdonglinux/artex`), and follow-on C2 reporting.

---

## 3. Open-Source Detection, Fingerprinting & Telemetry Standards

This workbench stands directly on the shoulders of the open-source security-engineering ecosystem:

- **SigmaHQ & `pySigma` / `sigma-cli`** (`https://github.com/SigmaHQ/sigma`, `https://github.com/SigmaHQ/pySigma`) — Vendor-neutral detection rule specification and multi-SIEM/XDR backend compilers (Elastic, Microsoft Kusto/MDE/Sentinel, CrowdStrike LogScale, Splunk, SentinelOne).
- **FoxIO JA4+ Network Fingerprinting** (`https://github.com/FoxIO-LLC/ja4`) — Open specifications for `JA4`, `JA4S`, `JA4H`, `JA4X`, and `JA4T` client/server/certificate fingerprinting.
- **CERT NetSA (`YAF` & `super_mediator`)** (`https://tools.netsa.cert.org/`) — Bidirectional IPFIX (RFC 5103) flow export, DPI (`silkAppLabel`), and TLS/JA4 enterprise information elements.
- **Zeek** (`https://zeek.org/`), **Suricata / OISF** (`https://suricata.io/`), **YARA** (`https://github.com/VirusTotal/yara`), **DuckDB** (`https://duckdb.org/`), and **MITRE ATT&CK®** (`https://attack.mitre.org/`).

---

## 4. Going Further — Independent Research Practices

To avoid single-source bias or stale indicators when defending your own environment:
1. **Verify Primary Sources:** Cross-check upstream repositories (`ThreatDefence/artex-detections`, `theori-io/aipt-detections`, `SigmaHQ/sigma`) and current vendor advisories for newly observed forks, binary builds, and post-exploitation payloads.
2. **Treat All Static IOCs as Perishable:** Never hardcode campaign IPs or domains into permanent firewall blocks without verifying current ownership/freshness via passive intelligence platforms.
3. **Validate Behavior Against Your Own Telemetry:** Run positive-control schema checks and 7-day shadow-mode dry runs (see [docs/soc_siem_validation_playbook.md](soc_siem_validation_playbook.md)) to measure real false-positive rates against your own NATs, CI runners, scanners, and developer workstations.
4. **Stay Safe While Researching:** Never browse or pull raw threat-actor directories from bare metal — review [docs/quarantine_sop.md](quarantine_sop.md) and [SECURITY.md](../SECURITY.md) before inspecting any external artifacts.
