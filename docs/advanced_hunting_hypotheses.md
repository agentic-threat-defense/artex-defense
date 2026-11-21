# Post-IOC / Next-Wave ARTEX Hunting Hypotheses

Once operators strip obvious static IOCs (`norma/0.4`, `artex-enrich/1.0`, `artex-readonly/1.0`, `ARTEX-worker/1.0`, `artx5v`, ports `8787`/`8790`, `ArtexProbe`), proxy LLM traffic through self-hosted VPS relays, and add pacing jitter, detection shifts to **structural invariants of LLM-driven multi-agent loops**.

---

## 1. Bimodal "LLM Think-Time" Cadence (Field-Confirmed by Unit 42)
- **Signal:** Neither uniform sub-second script noise (`0.05–0.5s`) nor heavy-tailed human pacing. Unit 42's Oct 30, 2026 report measured ARTEX in the wild at **bursts of 1–14 requests (~1/sec) separated by regular 25–31s inference pauses**, with zero diurnal fatigue and zero human typos.
- **Spec-Driven Targeting & Goal Verification (Unit 42):** Harvesting `*.js.map`, `/openapi.json`, `/docs`, `/redoc`, or `runtime-config.json` followed within **2–3 seconds** by calls to internal/write endpoints defined in those specs, `HTTP 422` validation self-correction retries, and **immediate `GET` read-back within 1–2s** after every successful `PUT`/`POST`/`PATCH` write.
- **Primary Telemetry / Stack:** Zscaler NSS, Cisco ASA/FTD, Citrix NetScaler, PAN-OS, F5 BIG-IP, MDE/CrowdStrike/S1 → **Spark SQL / Data-Lake** rolling inter-arrival distribution & autocorrelation scoring.

## 2. Unsynchronized Multi-Worker Collisions & Parallel Fan-Out
- **Redundant Recon Repeats:** Same compromised host/account running identical read-only recon commands (`whoami /all`, `nltest`, `ipconfig`, `id`) 3–5× within 2 minutes because separate worker intents (`i1`, `i2`, `i3`...) lack full shared stdout.
- **Simultaneous Multi-Surface Pivoting:** Single identity hitting Entra/Graph, Key Vault/Secrets, internal web portals, and AD/LDAP within the same 60s window.
- **JA4 / JA4H Stack Whiplash:** Single external IP hitting edge appliances with 3–4 distinct client stacks (`nmap` → Go `net/http` → Python `httpx` → `HeadlessChrome` → `curl`) within 90 seconds (**FoxIO JA4+** + Zeek/Proxy).

## 3. LLM Command-Line & Linguistic Fingerprints
- **Context-Budget Truncation Idioms:** Persistent use of `2>&1`, `| head -n 50`, `| Select-Object -First 20`, `--max-time 10`, `curl -sSk`, `| ConvertTo-Json -Depth 4`, or `echo "=== ... ==="` markers to keep output structured inside tool limits.
- **Toolbox Inventory Preambles:** Immediate `which nmap curl python3 jq nc 2>/dev/null` or `Get-Command` checks upon landing.
- **Typo-Free Semantic Self-Correction:** Failed OS/API command followed 5–15s later by a cleanly rewritten OS/API-compatible equivalent (zero human misspellings).

## 4. "Touch-and-Bail" EDR Blind-Spot Seeking & Deception
- **Negative-Space Hunt:** Internal account/IP authenticating to 5–15 hosts over SMB/WinRM/SSH, executing only 1–2 service/EDR checks (`sc query`, `tasklist`, `ps`) on EDR-protected hosts before disconnecting, then lingering heavily on an unmonitored host or legacy appliance.
- **Deception / Canary Tripwires:** Low-interaction canary legacy web portal (fake `/.env` with canary tokens, fake `/vpn/` or `/tmui/` endpoint) or canary "no-EDR" host inside an internal segment.

## 5. Growing-Context "Sawtooth" Network Flows (Self-Hosted LLM Proxies)
- **Signal:** Even when attackers proxy LLM traffic through a private VPS on TCP 443, multi-turn chat-completion loops produce **monotonically growing `bytes_out` per request** (`4 KB → 9 KB → 17 KB → 29 KB → 48 KB`, then reset — a sawtooth wave) paired with steady `1–5 KB` streamed downloads every 5–20s to a single rare VPS IP / newly registered domain.
- **Primary Telemetry / Stack:** Zscaler NSS, Zeek `conn.log`/`ssl.log`, PAN-OS/FTD traffic logs → **Spark SQL / Data-Lake** session flow analytics + **Team Cymru** IP/ASN enrichment.

## 6. Non-Human Identity (NHI) Scope-Expansion Drift
- **Signal:** Pre-existing Service Principals, OAuth apps, or backup/supply-chain integrations operating with **zero interactive user sign-ins** suddenly expanding beyond their 30-day API endpoint baseline (e.g., first-ever burst against Microsoft Graph `Directory.Read.All`, Key Vault, or AWS Secrets Manager).

## 7. Edge Error-Loop Friction & Soft-Tarpit Telemetry
- **Control + Signal:** Stripping verbose 4xx/5xx error bodies and applying mild rate-limit friction starves LLM error-correction loops and pushes autonomous agents into longer, more easily detected retry spirals.
