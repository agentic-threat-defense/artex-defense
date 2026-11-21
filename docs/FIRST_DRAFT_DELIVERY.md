# First-Draft Delivery Package: ARTEX, AntiFox & Autonomous Agentic Threat Detection Framework

> **Status:** First Draft — Ready for Internal Review and Shadow-Mode SIEM Validation *(further testing, schema alignment, and threshold tuning will be required for live or custom production environments)*
> **Classification / Provenance:** 100% Clean-Room Open-Source & Public Threat Intelligence (zero proprietary or internal data; zero unverified indicators)
> **Date:** 2026-11-21
>
> **WARNING — Operational Safety (Zero Bare-Metal Exposure):** Never browse, curl, download, or inspect raw attacker directories (`SimpleHTTP`), exposed operator consoles, or suspect C2 infrastructure from a bare-metal host or corporate workstation. Identify and triage exposed infrastructure strictly through passive intelligence platforms (e.g., **Censys**, **Shodan**, **Hunt.io**, **Google Threat Intelligence (GTI)**, **GreyNoise**, **Team Cymru**, **FOFA**, **Validin**, **Silent Push**, **URLScan.io**, or equivalent passive TI services). Any retrieved artifacts or `TaskID` transcripts must be inspected exclusively inside an isolated, snapshotted analysis VM (Tier 3 air-gapped KVM/QEMU) and sanitized/redacted (stripping victim IPs, domains, and credentials via `scripts/sandbox-analyze-tasks.sh` or `artex-hunt sanitize`) prior to offline analysis or rule tuning.

---

## 1. Executive Summary
Autonomous, LLM-driven offensive frameworks — led by **ARTEX** (`Autumn-27/ARTEX`), its rapidly proliferating forks (**AntiFox** [`AntiFox-AI/antifox`], **ScopeWeaver**, **Pojun**, **FORANG**, **ARTEX PRO**, **ARTEX MX**, **LUCK**, **Guanlan SEC**), and adjacent agentic tooling (**HexStrike**, **CyberStrikeAI**, **PentAGI**, **Cairn**) — compress multi-stage intrusions from days to **under 3 hours** across edge appliances, web/API portals, identity providers (Okta / Entra ID), cloud IAM (AWS / Azure), and endpoints.

Because operators trivially rotate residential proxy IPs, strip User-Agents, rename binaries, and front LLM proxies over standard TCP `443`, static IOC lists decay within hours. This package delivers a **defense-in-depth, Risk-Based Alerting (RBA) detection framework** pairing high-confidence static artifacts (**Tier A**) with **Zero-IOC behavioral detections** (**Tier B**) and enrichment pivots (**Tier C**). Further testing, field-schema alignment, and baseline tuning will be required for live or custom production environments.

---

## 2. Multi-Surface Coverage Matrix

| Surface | High-Fidelity Static & Forensic Coverage (Tier A) | Post-IOC Behavioral Coverage (Tier B) | Key Deliverables |
| :--- | :--- | :--- | :--- |
| **Edge Appliances** *(Cisco ASA/FTD, Citrix NetScaler, PAN-OS, F5 BIG-IP)* | WebVPN/Citrix/GlobalProtect/TMUI URI probing, `artex-enrich/1.0`, `norma/0.4`, self-proclaimed authorized UAs (`LLMLeak-RedTeam/`, `authorized-exposure-audit/`) | Rapid & throttled VPN auth sprays, **distributed residential proxy-pool probing**, bimodal LLM Think-Act pauses (18–60s) | Sigma (#3–5, #10), Suricata (`artex_edge_and_harness.rules`), Sentinel/Elastic/LogScale packs |
| **Web / API / WAF** | Unit 42 control-404 canaries (`zz_no_such_user`, `zzzrandom`), GreyNoise `artex=` param, `{"alg":"none"}` JWT spray (`eyJhbGciOiJub25l`), cloud metadata SSRF (`169.254.169.254`, Alibaba `100.100.100.200`), `/uploads/*.php\|jsp\|aspx` drops | Error-correction pivots (`4xx` → `200` sensitive path), **forced error-handling calibration** (multi-error-class `404`/`405`/`422`/`500` probing & keyword-free random-slug soft-404s), `.js.map`/`openapi.json` spec-driven targeting, REST resource Write→Readback, **NAT-safe `JA4`/`JA4H` client stack whiplash** | Sigma (#6, #10, #12), Suricata, Zeek, `detectors.py` |
| **Identity Providers (IdP / 2FA)** *(Okta & Microsoft Entra ID)* | Okta `deny_push`, `VERIFICATION_ERROR`, `user.mfa.factor.activate`, legacy `/api/v1/authn` failures; Entra `7000215`/`7000222` SP secret guessing, `500121` MFA bombing, `Register security info` | **Spray-Then-Success** (`>=5` failed accounts + `200`), **2FA push-bombing & rogue factor tampering**, SP secret-guess→success, **non-interactive SP multi-resource fan-out (`>=5` resources)** | Native Okta & Entra parsers, Sigma (#15–16), Entra KQL (#5–7), Okta ES\|QL (#8) |
| **Cloud Control Plane** *(AWS & Azure)* | CloudWatch `FilterLogEvents` secret search, EC2 `Client.DryRunOperation` sweeps, Azure Kudu (`*.scm.azurewebsites.net`) & `/deployments/validate`, AWS Cognito `CognitoIdentityCredentials` | **AntiFox multi-service AWS `AccessDenied` sweep** (IAM/EC2/S3/KMS/RDS/EKS/Bedrock) → `GetSecretValue` hit; **Entra SP `401`→`200`→Key Vault/SAS** pivot; multi-field REST/CLI IAM escalation | Sigma (#13), Elastic ES\|QL (#7), MDE/Sentinel KQL (#5–7) |
| **Endpoints & Operator Hosts** *(Windows & Linux)* | `BLOODALCHEMY` (`graphics-hook-filter64.dll`, `graphics-hook_config.bin`, `/Inform/logger/`), `ProgramData\artx5v\`, `/tasks/<id>/i<id>/cmd-output/`, `mitmproxy-ca-cert.pem` + `HTTP_PROXY` env injection, `xcai-effort-shim.py`, `xp_cmdshell`/`WinRing0x64.sys`, Kerberoast/DCSync/`vshell`/`AdaptixC2`/`WISP` | Compressed endpoint recon burst (`>=5` cmds in `<=35s`), **shell-wrapper-stripped redundant worker recon**, **LLM CLI context-budget idioms**, **touch-and-bail multi-host process checks**, tightened web-parent shell spawns | Sigma (#1, #7, #8, #11, #14), GTI Livehunt & Retrohunt YARA, `artex-hunt host-triage`, all 4 EDR packs |
| **Network & Encrypted Biflows** *(YAF IPFIX / RFC 5103, Zeek, JA4+)* | Console/proxy ports (`8787`, `8788`, `8790`, `8890`, `8090`), port-independent `silkAppLabel`, self-signed **`Issuer O=ARTEX`** X.509 cert (`C7A884AFCD...`), malicious LLM relays (`xcai[.]pro`, `lanmao666[.]com`, `sqlserver-sqlite[.]com`) | **Encrypted TLS 1.3 Sawtooth Growing-Context LLM Proxy** (`octetTotalCount` / `reverseOctetTotalCount`, compaction-resilient), **Raw-IP TLS (`t13i`/`t12i`)**, **`JA4X_c` + `JA4S` + Team Cymru ASN clustering** | Native YAF/IPFIX parser, `production_adaptation_pack.md`, Zeek, Suricata, TI hunting guide |

---

## 3. Empirical Verification & Anti-Echo-Chamber Scorecard

To prevent single-author bias, every detection layer was validated against both an automated synthetic/adversarial suite **and** two rounds of **blind out-of-distribution stress testing** (independently generated by an isolated local 26B LLM with zero access to detector code or rules):

| Verification Gate | Result | Evidence File |
| :--- | :--- | :--- |
| **Automated Unit, Integration, Parser & Lab Suite** | **40 / 40 passed** | `tests/` |
| **28-Dataset Multi-Surface Precision / Recall Eval** | **Precision `100.00%` \| Recall `100.00%`** (`TP=15, FP=0, TN=13, FN=0`) | `tests/test_eval_harness.py` |
| **Zero-IOC Adversarial Evasion Proof** | **4 / 4** caught with **0 static IOC tokens** and **0 static reasons** | `tests/test_zero_ioc_evasion.py` |
| **Adversarial Mutations, Forced Error Calibration & Noise Traps** | All mutations & error-forcing patterns caught; **0 FPs** (`AbnormalSecurity`, `Normalizer.exe`, Jenkins `java->bash`, `POST /cart`, UUID `404`s, laptop LLM) | `tests/test_adversarial_mutations.py` |
| **Blind Out-of-Distribution Stress Test (Round 1 → Fixed)** | Exposed `4/8` FPs & `5/8` FNs → fixed to **`0/8` FPs \| `0/8` FNs** (RBA `alert` tier) | `docs/blind_stress_test_log.md` |
| **Zero-Edit Held-Out Blind Generalization Test (Round 2)** | **`0/5` Benign FPs \| `0/5` Attack FNs** (evaluated with zero code edits allowed) | `docs/blind_stress_test_log.md` |
| **Multi-Backend `pySigma` Compilation (16 Rules)** | **0 schema issues**; `16/16` Elastic ES\|QL, Lucene, KQL, CrowdStrike LogScale CQL, Splunk SPL; `5/5` MDE XDR, Sentinel ASIM, SentinelOne S1QL | `rules/queries/compiled_sigma/` |
| **GTI Enterprise Livehunt & Retrohunt YARA** | Verified compiling cleanly on Google Threat Intelligence console | `rules/yara/` |
| **Read-Only Operator Host Triage (`artex-hunt host-triage`)** | `CLEAN (0 findings)` on benign host; `6/6` forensic categories detected on simulated relay | `tests/test_host_triage.py` |
| **Air-Gapped KVM/QEMU Lab Scaffold (`lab/kvm/`)** | Verified zero `<forward>` air-gap invariant, zero cloud-init gateways, valid `cidata` ISOs, raw Zeek JSON + Auditd converter | `tests/test_kvm_lab.py` |

---

## 4. Artifact Inventory & Recommended Rollout Plan

### Key Handoff Files
1. **Production Schema Adaptation Pack (YAF Bidirectional IPFIX + Team Cymru + JA4X):** `docs/production_adaptation_pack.md`
2. **SOC Shadow-Mode SIEM Validation Playbook:** `docs/soc_siem_validation_playbook.md`
3. **Blind Stress-Test FP/FN Audit Trail:** `docs/blind_stress_test_log.md`
4. **Compiled Multi-SIEM Rule Packs:** `rules/queries/compiled_sigma/` + hand-crafted packs (`elastic_ech_eql.eql`, `microsoft_mde_kql.kql`, `crowdstrike_logscale_cql.cql`, `sentinelone_s1ql.s1ql`)
5. **External TI & Infrastructure Hunting Templates (GTI, Censys, Shodan, Hunt.io, Team Cymru, FoxIO JA4+, GreyNoise, YAF IPFIX):** `rules/intel_hunting/enterprise_intel_hunt_queries.md`
6. **Network & Binary Rules:** `rules/network/artex_edge_and_harness.rules`, `rules/network/artex_agentic_cadence.zeek`, `rules/yara/`
7. **Threat Model, Hardening & Primary Source Credits:** `docs/artex_threat_model.md`, `docs/edge_to_endpoint_hardening.md`, `docs/intel_corpus/artex_public_advisories_2026_11.md`, `docs/REFERENCES_AND_ACKNOWLEDGMENTS.md` *(please review primary upstream research directly rather than treating this package as standalone ground truth)*

### 3-Step Internal Deployment Sequence
1. **Step 1 — Schema Alignment & Environment Tailoring:** Map placeholder column names, timestamp units, CMDB server-role tables, and authorized scanner IP/CIDR allowlists in `docs/production_adaptation_pack.md` to live production tables. *(Further testing and tuning will be required for live or custom environments.)*
2. **Step 2 — Positive-Control + 7-Day Shadow Mode:** Run the positive-control schema check (confirming every query returns rows on a benign test value) followed by a 7-day dry run to measure Alert Volume per Day (AVD) and tune out corporate NATs, CI runners, and authorized scanners.
3. **Step 3 — Phased RBA Promotion:** Promote **Tier A** standalone alerts first (`BLOODALCHEMY`, `alg:none` JWT, Okta/Entra 2FA bombing & factor tampering, SP secret-guess→success, SSRF/upload webshells, `w3wp -> shell`, `artex-enrich/1.0`/`norma/0.4`), followed by **Tier B** correlated behavioral alerts (sawtooth encrypted LLM flows, forced error-handling calibration, AntiFox AWS `AccessDenied` sweeps, NAT-safe JA4 whiplash, distributed proxy-pool sprays), keeping **Tier C** items strictly as hunting/enrichment context.
