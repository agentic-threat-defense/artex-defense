# Adversarial Review Board for Detection Engineering

Detection rules—whether hand-written or AI-assisted—suffer from a predictable failure mode: **the synthetic echo chamber**. When the same person (or conversation context) writes the threat model, builds the synthetic fixtures, writes the detectors, and runs the evaluation harness, `100%` precision and recall only proves the code matches its own assumptions.

This document defines the **5-seat Adversarial Review Board** used to audit `artex-defense` before releases. It is deliberately **model- and tool-agnostic**: teams can run it with independent LLM sessions (ideally across distinct stock model families), human peer-review rotations, or a hybrid of both.

---

## Operating Rules (Non-Negotiable)

Without hard constraints, multi-persona reviews devolve into vague praise, patch oscillation, or repetitive platitudes. Every seat obeys six rules:

1. **Strict Context Firewall & Read-Only Tool Isolation:** Each reviewer starts with a fresh, isolated context containing **zero** prior design rationale or build history, and holds **read-only** access to repository files, fixtures, and diffs. Only a dedicated Builder role edits code; **Seat 5 (CTO Gate)** is strictly barred from modifying files so it never grades its own homework.
2. **Proof or Silence:** No speculative advice (*"this might cause false positives"*). Every finding must cite an exact `file:line`, provide a concrete benign enterprise payload (for FPs) or a concrete 1-line bypass (for evasion), and classify evasion gaps as either **`Fixable Logic Gap`** or **`Fundamental Physics Limit`**.
3. **Cross-Model Independence:** Never audit a custom-prompted model using that same custom-prompted model as judge. Custom Modelfiles or system prompts are *code under test*; board seats run on stock, uncustomized models (or independent human reviewers).
4. **No Patch Without a Regression Fixture *(Deterministic Enforcement Over Prompt Hope)*:** Every accepted finding from Seats 1–4 and every Seat 5 `HOLD` blocker must wire its exact repro payload into `tests/` (e.g., `tests/test_rule_pack_hygiene.py`, parser tests, or FP guards). Code-only patches without a corresponding permanent test fail the release gate automatically.
5. **Real-Engine Verification Over Eyeballing:** Static LLM review catches semantic bugs well but frequently misses engine-specific parser quirks (e.g., unescaped `;` inside Suricata `pcre:"..."`). Rule-pack changes must pass real-engine validation (`suricata -T`, Zeek LTS, YARA, `artex-hunt sigma-compile` zero-drift checks, and host-only isolated lab runs) before release.
6. **Two-Phase `GO` / `HOLD` Release Gate (2-Wave Cap):** Seats 1–4 audit in parallel. After fixes and regression tests are written, **Seat 5 (CTO Chair)** audits the *patch diff itself* for second-order "fix-the-fix" regressions and missing test fixtures, issuing `VERDICT: GO` or `VERDICT: HOLD`. If a Seat 1 (SOC) vs. Seat 2 (Red-Team) tradeoff cannot be resolved cleanly within **2 patch waves**, Seat 5 reclassifies the bypass to `hunt`/`info` tier or Future Backlog (`Fundamental Physics Limit`) rather than overtuning `alert` rules.

---

## Board Roster (5 Tight Seats — Split Seat 4A/4B, No Committee Bloat)

Keep the board capped at **5 tightly scoped seats** with explicit tool isolation. Adding generic management or compliance seats dilutes signal; splitting Seat 4 into two narrow passes prevents cross-dialect syntax blindness as rule packs grow.

| Seat | Role | Access | Primary Failure Mode Owned | Explicit Non-Overlap Boundary |
| :--- | :--- | :--- | :--- | :--- |
| **Seat 1** | **Cynical SOC Lead** *(Alert-Fatigue Auditor)* | Read-only | Production false positives from real enterprise noise (SWGs like Zscaler/Netskope, Terraform/CSPM/CI-CD, SPA/Swagger/QA, SSO bursts, Ansible/SCCM, single-event Sigma noise) | Does not evaluate offensive evasion or code security; must provide concrete benign JSON/log payloads reaching `alert` or Sigma `high`. |
| **Seat 2** | **Offensive Red-Teamer** *(Sub-Hunt Evasion Auditor)* | Read-only | Cheapest 1-line attacker tweaks that evade the **`hunt` threshold (`risk_score < 45`)** and break cross-surface kill-chain correlation | Must separate `Fixable Logic Gap` from `Fundamental Physics Limit` (e.g., slow randomized jitter) so defenders do not overtune. |
| **Seat 3** | **AppSec, AI-Safety & Leakage Auditor** *(Engineering Integrity)* | Read-only | Parser crashers on malformed input, sandbox/MCP/sanitizer bypasses, indirect prompt injection & delimiter spoofing in untrusted feeds/telemetry, `README` claims vs. actual code, and **`simulator` ↔ `detector` synthetic leakage** | Focuses on attack surface, AI-safety fencing, truthfulness, and test-harness integrity rather than SIEM threshold tuning. |
| **Seat 4A / 4B** | **Real-Wire Schema & SIEM Engineer** *(Permanent Split Specialist)* | Read-only | **Pass 4A (Wire & Host/Network Rules):** Raw vendor log normalization (AWS CloudTrail S3 `{"Records":[...]}`, RFC 3164 syslog, IdP JSON, YAF IPFIX, Linux `auditd`) + Sigma YAML, YARA, Suricata (sticky buffers/delimiters), and Zeek.<br>**Pass 4B (Compiled SIEM & Passive Intel):** ES\|QL, Lucene, KQL/MDE/ASIM, LogScale CQL, Splunk SPL, S1QL, and Censys CenQL/GreyNoise/HuntSQL syntax & field fidelity. | Audits wire/schema/query fidelity across two narrow dialect passes; does not duplicate Seat 1 behavioral threshold critiques. |
| **Seat 5** | **Independent CTO / Chief Architect Chair** *(Release Gate)* | Read-only *(never edits code)* | **Second-order "fix-the-fix" regressions**, missing regression fixtures, conflicting SOC vs. Red-Team tradeoffs (enforcing the 2-wave cap), and schema splits introduced by patches | Runs *after* fixes are drafted; audits the diff and issues `VERDICT: GO` or `VERDICT: HOLD` with blockers separated from future backlog. |

---

## Reusable Seat Briefs

Teams adapting this workflow for their own Sigma, SIEM, or Python detection repositories can use these minimal briefs directly in isolated, read-only sessions:

<details>
<summary><strong>Seat 1 Brief — Cynical SOC Lead (Alert-Fatigue Auditor)</strong></summary>

```text
You are Seat 1 on an independent Adversarial Review Board: the Cynical SOC Lead / Alert-Fatigue Auditor.
You have READ-ONLY access and no loyalty to the authors. Read the actual detector code and Sigma rules.
Find the top 5-7 realistic enterprise FALSE-POSITIVE traps NOT already blocked by existing guards
(audit against Zscaler/Netskope SWGs, Terraform/Wiz/CI-CD, SPA/Swagger/QA, Okta/Entra SSO bursts,
Ansible/SCCM management hosts, and single-event high-severity Sigma rules).
STRICT RULES:
- Verify the actual code before claiming a bug; do not flag rules already capped below alert tier.
- Every finding must include: exact file:line, a concrete benign JSON/log sequence that triggers an
  alert/high rule (ready to wire into tests/), severity, and a surgical non-overtuned fix.
```

</details>

<details>
<summary><strong>Seat 2 Brief — Offensive Red-Teamer (Sub-Hunt Evasion Auditor)</strong></summary>

```text
You are Seat 2 on an independent Adversarial Review Board: the Offensive Red-Teamer (Evasion Auditor).
You have READ-ONLY access. Read the actual detector engine and network rules. Find the top 5-7 cheapest,
highest-impact bypasses that let an operator complete recon, secret harvesting, or post-exploitation while
staying below the HUNT threshold (risk_score < 45) AND breaking cross-surface kill-chain correlation.
STRICT RULES:
- Verify exact code conditions before claiming a bypass.
- Every finding must include: exact file:line, the concrete 1-line attacker tweak (ready to wire into tests/),
  classification ("Fixable Logic Gap" vs. "Fundamental Physics Limit"), and a low-FP hardening idea if fixable.
```

</details>

<details>
<summary><strong>Seat 3 Brief — AppSec, AI-Safety & Synthetic-Leakage Auditor</strong></summary>

```text
You are Seat 3 on an independent Adversarial Review Board: the AppSec, AI-Safety & Engineering Integrity Auditor.
You have READ-ONLY access. Inspect README/docs, synthetic data generators, parsers, sanitizer, Watchtower feed
fetchers, LLM worker fencing, and MCP/CLI/Docker sandbox wrappers.
Find the top 5-7 real issues across:
1. Synthetic generator-detector leakage (clean synthetic fields/timings that vanish in messy real logs).
2. Parser crashers on malformed, truncated, or out-of-order telemetry (JSON, XML, PCAP, Auditd, syslog).
3. Real AppSec & AI-safety bugs: path traversal, XML/DTD bypasses, indirect prompt injection via untrusted
   RSS/Atom/GitHub commit payloads, delimiter spoofing inside UNTRUSTED_INTEL fences, defang-reversal tricks
   (Unicode homoglyphs, nested markdown links), and unescaped terminal markup.
4. Documentation claims that overstate what the code or isolation boundaries actually prove.
Every finding must cite exact file:line and a concrete repro payload ready to wire into tests/.
```

</details>

<details>
<summary><strong>Seat 4 Brief — Real-Wire Schema & SIEM Engineer (Split 4A / 4B Execution)</strong></summary>

```text
You are Seat 4 on an independent Adversarial Review Board: the Real-Wire Schema & SIEM Engineer.
You have READ-ONLY access. Run as two narrow passes to prevent cross-dialect syntax blindness:

- Pass 4A (Wire Format & Host/Network Rules):
  Compare raw vendor exports (AWS CloudTrail S3 {"Records":[...]}, RFC 3164 syslog, Okta/Entra/Duo/
  Ping/GWS JSON, Sysmon, Linux Auditd, Zeek JSON, YAF IPFIX) against parsers, Sigma YAML, YARA,
  Suricata (sticky buffers, option delimiters, classtypes, threshold/detection_filter), and Zeek scripts.

- Pass 4B (Compiled SIEM & Passive Intel Packs):
  Audit compiled and hand-written query packs (Elastic ES|QL & Lucene, Microsoft KQL/MDE/ASIM,
  CrowdStrike LogScale CQL, Splunk SPL, SentinelOne S1QL) and passive intel templates (Censys CenQL,
  GreyNoise GNQL, HuntSQL, Shodan) for invalid operators, case-sensitivity traps, quoted-keyword typing,
  and field-name mismatches yielding 0% recall on unmodified production exports.

Every finding must cite exact file:line and a concrete raw log, rule snippet, or query repro.
```

</details>

<details>
<summary><strong>Seat 5 Brief — Independent CTO / Chief Architect Chair (Release Gate)</strong></summary>

```text
You are Seat 5: the Independent CTO / Chief Architect Chair performing a pre-ship release gate review.
You have STRICT READ-ONLY access and must NEVER edit code yourself.
Inspect the candidate release diff and surrounding code strictly for:
1. Second-order "fix-the-fix" regressions introduced by recent patches.
2. Missing permanent regression tests: automatically HOLD if a blocker fix in src/ or rules/ lacks a
   corresponding benign FP or evasion repro fixture in tests/.
3. Unintended SOC-vs-Red-Team collisions or schema splits between parsers, detectors, and tests.
4. Any concrete P0 bug, syntax error, or security bypass that would embarrass the project on clone.
STRICT FORMAT:
- Begin with "VERDICT: GO" (zero release blockers) or "VERDICT: HOLD" (>=1 concrete blocker).
- Cite exact file:line and a concrete repro for every blocker.
- Separate Release Blockers from Non-Blocking Future Backlog.
- 2-Wave Cap: If a SOC-vs-Red-Team tension cannot be resolved cleanly within 2 patch waves, reclassify
  the bypass to hunt/info tier or Future Backlog (Fundamental Physics Limit) rather than overtuning alerts.
```

</details>

---

## Proof of Value: What This Board Caught on `artex-defense` (`v0.1.0` – `v0.2.2`)

Across every release wave, running this board (paired with real-engine validation) caught concrete production blockers on codebases that already passed 100% of their existing unit tests:

| Caught By | Concrete Finding (With Repro) | Resolution & Permanent Guard |
| :--- | :--- | :--- |
| **Seat 1 (SOC Lead)** | Single Chrome SPA session generated 3+ `JA4H` hashes across `GET`/`POST`, triggering `ja4_client_stack_whiplash` (`70`); `200 OK` MongoDB ObjectIDs/ULIDs triggered random-slug calibration. | Gated `JA4H` whiplash on `>=2` UAs + non-asset errors; restricted `200 OK` soft-404s to root-level non-hex probes (`len(parts) <= 1`). |
| **Seat 2 (Red-Team)** | Spoofing `User-Agent: Terraform/1.9` muted 4 high-severity CloudTrail detectors (`80–90 → 0`); confirmed C2 relays (`artex.lol`, `xcai.pro`) scored only `65` (`hunt`). | Replaced UA-only suppression with bounded IAM role identity matching; promoted malicious C2 relays to `95` (`alert`). |
| **Seat 3 (AppSec / Leakage)** | Native AWS CloudTrail JSON hit `0%` recall in `parsers.py` (masked by flat dicts in `simulator.py`); `"status": "success"` mapped to `403`; `scan --sanitize` skipped stdout; JSON `"password": "..."` leaked unredacted. | Built native CloudTrail parser + migrated `simulator.py` to raw CloudTrail JSON; fixed status mapping; sanitized stdout + escaped Rich markup; closed JSON/dict/URI sanitizer gaps. |
| **Seat 4A / 4B (`v0.1.x`–`v0.2.0`)** | Compiled KQL emitted `''c-uri''` & string-quoted integer ports; ES\|QL emitted mixed-case literals against `*.caseless`; Sigma `vshell` matched Visual Studio `Enter-VsDevShell` (`critical`); `oast.live` matched `toast.live`; YARA `"artex"+"planner"` hit Go `StartExecution` binaries; Suricata used invalid `classtype:exfiltration;` & `norma` matched `"normal"`; Sentinel `50074` triggered MFA-prompt storms; LogScale/ES\|QL/S1QL operator bugs; legacy Censys/HuntSQL/GNQL syntax. | Hardened pySigma backends & pipelines; split Windows/Linux endpoint Sigma rules; hardened all 20 Sigma, 3 YARA, Suricata, Zeek, SIEM, and passive-TI packs; locked regressions in `tests/test_rule_pack_hygiene.py`. |
| **Real-Engine Validation (`v0.2.1`)** | Live `suricata -T` (7.0.3) crashed loading `sid:9100014` on unescaped `;` inside `pcre:"..."`; live Debian 12 KVM `auditd` revealed `success=no` `ENOENT` PATH-lookup phantom events, `$HOME` `0700` QEMU traversal failure, and invisible SATA CD-ROM on `linux-image-cloud-amd64`. | Escaped `\x3b` + added permanent Suricata semicolon guard in `tests/test_rule_pack_hygiene.py`; separated `IMAGE_DIR` (`0755`), switched NoCloud seed to `virtio`, filtered `auditd` `success=no`, and resolved `ppid` → `parent_process`. |
| **Seat 5 (CTO Gate — `HOLD` → `GO`)** | Caught across multiple waves: (1) S3 CloudTrail `{"Records":[...]}` scanning as `0` events & XML comment DTD bypass `<!-- <rss> --><!DOCTYPE ...>`; (2) `detectors.py` firing `100 alert` on benign `/favicon.ico` + `/nonexistent-image.png` + `/.env.example`; (3) fresh human web-LLM chat (`4KB→22KB`, 18s pauses) triggering `llm_sawtooth_context_flow` (`70 alert`) & double-scoring persistent TLS loops; (4) Censys CenQL `.http.uri` vs. `.path` and Cisco IOS XE `dir flash: /recursive` flag order. | Fixed every blocker with permanent pytest regressions (`tests/test_watchtower_updates.py`, `tests/test_kvm_lab.py`, `tests/test_rule_pack_hygiene.py`, real `xml.parsers.expat` handlers) before Seat 5 flipped each wave to `VERDICT: GO`. |

---

## Open Invitation to Improve This Pattern

This board charter is an open working pattern, not a finished standard. Pull requests and discussions are welcome for:
- Sharper seat boundaries or failure modes we missed.
- Better adversarial repro checklists for SIEM/XDR rules, real network sensors, and log parsers.
- Uncurated benign enterprise telemetry profiles that stress-test false-positive rates outside synthetic suites.
