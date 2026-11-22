# Adversarial Review Board for Detection Engineering

Detection rules—whether hand-written or AI-assisted—suffer from a predictable failure mode: **the synthetic echo chamber**. When the same person (or conversation context) writes the threat model, builds the synthetic fixtures, writes the detectors, and runs the evaluation harness, `100%` precision and recall only proves the code matches its own assumptions.

This document defines the **5-seat Adversarial Review Board** used to audit `artex-defense` before releases. It is deliberately **model- and tool-agnostic**: teams can run it with independent LLM sessions (ideally across distinct stock model families), human peer-review rotations, or a hybrid of both.

---

## Operating Rules (Non-Negotiable)

Without hard constraints, multi-persona reviews devolve into vague praise or repetitive platitudes. Every seat obeys four rules:

1. **Strict Context Firewall:** Each reviewer starts with a fresh, isolated context containing **zero** prior design rationale or build history. Seats read only repository files and diffs.
2. **Proof or Silence:** No speculative advice (*"this might cause false positives"*). Every finding must cite an exact `file:line`, provide a concrete benign enterprise payload (for FPs) or a concrete 1-line bypass (for evasion), and classify evasion gaps as either **`Fixable Logic Gap`** or **`Fundamental Physics Limit`**.
3. **Cross-Model Independence:** Never audit a custom-prompted model using that same custom-prompted model as judge. Custom Modelfiles or system prompts are *code under test*; board seats run on stock, uncustomized models (or independent human reviewers).
4. **Two-Phase `GO` / `HOLD` Release Gate:** Seats 1–4 audit the codebase in parallel. After fixes are written, **Seat 5 (CTO Chair)** audits the *patch diff itself* specifically for second-order "fix-the-fix" regressions and issues an explicit `VERDICT: GO` or `VERDICT: HOLD`.

---

## Board Roster (5 Tight Seats — No Committee Bloat)

Keep the board capped at **4 core seats + 1 specialist Schema seat**. Adding generic management or compliance seats dilutes signal.

| Seat | Role | Primary Failure Mode Owned | Explicit Non-Overlap Boundary |
| :--- | :--- | :--- | :--- |
| **Seat 1** | **Cynical SOC Lead** *(Alert-Fatigue Auditor)* | Production false positives from real enterprise noise (SWGs like Zscaler/Netskope, Terraform/CSPM/CI-CD, SPA/Swagger/QA, SSO bursts, Ansible/SCCM, single-event Sigma noise) | Does not evaluate offensive evasion or code security; must provide concrete benign JSON/log payloads reaching `alert` or Sigma `high`. |
| **Seat 2** | **Offensive Red-Teamer** *(Sub-Hunt Evasion Auditor)* | Cheapest 1-line attacker tweaks that evade the **`hunt` threshold (`risk_score < 45`)** and break cross-surface kill-chain correlation | Must separate `Fixable Logic Gap` from `Fundamental Physics Limit` (e.g., slow randomized jitter) so defenders do not overtune. |
| **Seat 3** | **AppSec & Leakage Auditor** *(Engineering Integrity)* | Parser crashers on malformed input, sandbox/MCP/sanitizer bypasses, `README` claims vs. actual code, and **`simulator` ↔ `detector` synthetic leakage** | Focuses on attack surface, truthfulness, and test-harness integrity rather than SIEM threshold tuning. |
| **Seat 4** | **Real-Wire Schema & SIEM Engineer** *(Optional Specialist)* | Wire-format fidelity across real vendor exports (AWS CloudTrail S3 `{"Records": [...]}`, RFC 3164 syslog, native IdP JSON, YAF IPFIX) and compiled Sigma/ES\|QL/KQL/SPL/CQL field names & case-sensitivity | Audits schema/pipeline translation only; does not duplicate Seat 1 behavioral threshold critiques. |
| **Seat 5** | **Independent CTO / Chief Architect Chair** *(Release Gate)* | **Second-order "fix-the-fix" regressions**, conflicting SOC vs. Red-Team tradeoffs, and schema splits introduced by patches | Runs *after* fixes are drafted; audits the diff and issues `VERDICT: GO` or `VERDICT: HOLD` with blockers separated from future backlog. |

---

## Reusable Seat Briefs

Teams adapting this workflow for their own Sigma, SIEM, or Python detection repositories can use these minimal briefs directly in isolated sessions:

<details>
<summary><strong>Seat 1 Brief — Cynical SOC Lead (Alert-Fatigue Auditor)</strong></summary>

```text
You are Seat 1 on an independent Adversarial Review Board: the Cynical SOC Lead / Alert-Fatigue Auditor.
You have no loyalty to the authors. Read the actual detector code and Sigma rules.
Find the top 5-7 realistic enterprise FALSE-POSITIVE traps NOT already blocked by existing guards
(audit against Zscaler/Netskope SWGs, Terraform/Wiz/CI-CD, SPA/Swagger/QA, Okta/Entra SSO bursts,
Ansible/SCCM management hosts, and single-event high-severity Sigma rules).
STRICT RULES:
- Verify the actual code before claiming a bug; do not flag rules already capped below alert tier.
- Every finding must include: exact file:line, a concrete benign JSON/log sequence that triggers an
  alert/high rule, severity, and a surgical non-overtuned fix.
```

</details>

<details>
<summary><strong>Seat 2 Brief — Offensive Red-Teamer (Sub-Hunt Evasion Auditor)</strong></summary>

```text
You are Seat 2 on an independent Adversarial Review Board: the Offensive Red-Teamer (Evasion Auditor).
Read the actual detector engine and network rules. Find the top 5-7 cheapest, highest-impact bypasses
that let an operator complete recon, secret harvesting, or post-exploitation while staying below the
HUNT threshold (risk_score < 45) AND breaking cross-surface kill-chain correlation across two surfaces.
STRICT RULES:
- Verify exact code conditions before claiming a bypass.
- Every finding must include: exact file:line, the concrete 1-line attacker tweak, classification
  ("Fixable Logic Gap" vs. "Fundamental Physics Limit"), and a low-FP hardening idea if fixable.
```

</details>

<details>
<summary><strong>Seat 3 Brief — AppSec & Synthetic-Leakage Auditor</strong></summary>

```text
You are Seat 3 on an independent Adversarial Review Board: the AppSec & Engineering Integrity Auditor.
Inspect README/docs, synthetic data generators, parsers, sanitizer, MCP/CLI wrappers, and feed fetchers.
Find the top 5-7 real issues across:
1. Synthetic generator-detector leakage (clean synthetic fields/timings that vanish in messy real logs).
2. Parser crashers on malformed/truncated/out-of-order telemetry.
3. Real AppSec bugs (path traversal, XML/DTD, sanitizer/fencing bypasses, unescaped terminal markup).
4. Documentation claims that overstate what the code actually proves.
Every finding must cite exact file:line and concrete repro proof.
```

</details>

<details>
<summary><strong>Seat 4 Brief — Real-Wire Schema & SIEM Engineer (Optional Specialist)</strong></summary>

```text
You are Seat 4 on an independent Adversarial Review Board: the Real-Wire Schema & SIEM Engineer.
Compare raw vendor log schemas (AWS CloudTrail S3 {"Records":[...]}, RFC 3164 syslog, Okta/Entra/Duo/
Ping/GWS JSON, Sysmon, YAF IPFIX) against the repo's parsers, Sigma YAML rules, and compiled SIEM/XDR
query packs (ES|QL, Lucene, KQL/MDE/ASIM, LogScale CQL, Splunk SPL, S1QL).
Flag exact file:line field-name mismatches, case-sensitivity traps, nested-field drops, or pipeline
assumptions that silently yield 0% recall on unmodified production exports.
```

</details>

<details>
<summary><strong>Seat 5 Brief — Independent CTO / Chief Architect Chair (Release Gate)</strong></summary>

```text
You are Seat 5: the Independent CTO / Chief Architect Chair performing a pre-ship release gate review.
Inspect the candidate release diff and surrounding code strictly for:
1. Second-order "fix-the-fix" regressions introduced by recent patches.
2. Unintended SOC-vs-Red-Team collisions or schema splits between parsers, detectors, and tests.
3. Any concrete P0 bug or security bypass that would embarrass the project on clone.
STRICT FORMAT:
- Begin with "VERDICT: GO" (zero release blockers) or "VERDICT: HOLD" (>=1 concrete blocker).
- Cite exact file:line and a concrete repro for every blocker.
- Separate Release Blockers from Non-Blocking Future Backlog.
```

</details>

---

## Proof of Value: What This Board Caught on `artex-defense` (`v0.1.0`)

Before pushing commits `aa5cefc` and `95f9e30`, running this exact board against a codebase that already passed 100% of its own unit and synthetic evaluation tests uncovered real production blockers:

| Caught By | Concrete Finding (With Repro) | Resolution |
| :--- | :--- | :--- |
| **Seat 1 (SOC Lead)** | Single Chrome SPA session generated 3+ `JA4H` hashes across `GET`/`POST`, triggering `ja4_client_stack_whiplash` (`70`); `200 OK` MongoDB ObjectIDs/ULIDs triggered random-slug calibration. | Gated `JA4H` whiplash on `>=2` UAs + non-asset errors; restricted `200 OK` soft-404s to root-level non-hex probes (`len(parts) <= 1`). |
| **Seat 2 (Red-Team)** | Spoofing `User-Agent: Terraform/1.9` muted 4 high-severity CloudTrail detectors (`80–90 → 0`); confirmed C2 relays (`artex.lol`, `xcai.pro`) scored only `65` (`hunt`). | Replaced UA-only suppression with bounded IAM role identity matching; promoted malicious C2 relays to `95` (`alert`). |
| **Seat 3 (AppSec / Leakage)** | Native AWS CloudTrail JSON hit `0%` recall in `parsers.py` (masked by flat dicts in `simulator.py`); `"status": "success"` mapped to `403`; `scan --sanitize` skipped stdout; JSON `"password": "..."` leaked unredacted. | Built native CloudTrail parser + migrated `simulator.py` to raw CloudTrail JSON; fixed status mapping; sanitized stdout + escaped Rich markup; closed JSON/dict/URI sanitizer gaps. |
| **Seat 4 (Real-Wire Schema & SIEM)** | Compiled KQL emitted invalid `''c-uri''` double-quoted fields and string-quoted integer ports (`RemotePort in~ ("8787", ...)`); Elastic ES\|QL emitted mixed-case literals against lowercase `*.caseless` fields (`0%` recall + broken `Program Files` allowlist); SentinelOne emitted `DstPort In Contains AnyCase`; CloudTrail/Okta/Entra Sigma rules used synthetic `Action`/`CommandLine` fields instead of native vendor JSON fields; Cisco ASA rule ANDed mutually exclusive syslog + WebVPN URI fields. | Hardened Kusto, ES\|QL, and SentinelOne pySigma backends + custom ECS/KQL/Splunk real-wire pipelines; migrated CloudTrail/Okta/Entra/DNS/Proxy/ASA Sigma rules to native vendor fields; added dotted `raw_json` lookup in `eval_harness.py` and a permanent compiled-query linter + raw-JSON regression test suite. |
| **Seat 4 (Full Rule-Pack Hygiene — `v0.2.0`)** | 3-specialist sweep across all 5 `rules/` directories caught: Sigma `vshell` matching Visual Studio `Enter-VsDevShell` (`critical`), C2 relays suppressed on `LAPTOP-*` in Sigma/Zeek/KQL/CQL, bare `/+CSCOE+/` & `oast.live`→`toast.live` FPs, YARA `"artex"+"planner"` hitting Go `StartExecution` binaries + un-gated VT Livehunt PE branch, Suricata invalid `classtype:exfiltration;` + `norma` matching `"normal"` + missing HTTP sticky buffer, Zeek unbounded UA `$identifier`, Sentinel `50074` MFA-prompt FP storm, LogScale invalid `IN [...]`/`!=/regex/`, ES\|QL `RLIKE "(?i)"`, S1QL invalid `\| bucket 30s` & inverted `src`/`tgt` lineage, and legacy Censys/HuntSQL/GNQL syntax. | Hardened all 20 Sigma rules (split Windows/Linux AD pivot & staging compiler, enabled Linux endpoint compilation in MDE/ASIM/S1QL), all 3 YARA rules, Suricata + Zeek packs, all 4 hand-written SIEM packs, and passive intel templates; added permanent `tests/test_rule_pack_hygiene.py` regression guards. |
| **Seat 5 (CTO Gate — `HOLD`)** | Caught 6 second-order regressions in the first patch wave: S3 CloudTrail `{"Records": [...]}` silently scanning as `0` events; bipartite `(dst_a & dst_b)` merging unrelated `ec2.amazonaws.com` alerts; broad `service-role` matching compromised Lambda roles; regex XML prolog DTD check bypassed via `<!-- <rss> --><!DOCTYPE ...>`. | Unwrapped S3 `{"Records": [...]}`; isolated `distributed:` targets; tightened `CLOUD_IAC_ACTOR_ROLE_RE` + Pass 9 IP validation; replaced regex DTD guard with real `xml.parsers.expat` handlers. Re-verified `VERDICT: GO`. |

---

## Open Invitation to Improve This Pattern

This board charter is an open working pattern, not a finished standard. Pull requests and discussions are welcome for:
- Sharper seat boundaries or failure modes we missed.
- Better adversarial repro checklists for SIEM/XDR rules and log parsers.
- Uncurated benign enterprise telemetry profiles that stress-test false-positive rates outside synthetic suites.
