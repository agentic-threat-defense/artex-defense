# ARTEX & Autonomous Agentic Threats — Production Schema Adaptation Pack

> **Purpose:** 100% open-source, schema-parameterized detection blueprint built from public threat intelligence (Unit 42, FBI/IC3, CrowdStrike, Microsoft, Google GTIG, Elastic, ThreatDefence, Theori AIPT, Hunt.io, GreyNoise, `@BushidoToken`, CERT NetSA IPFIX/YAF) and validated against blind out-of-distribution chaos tests (`0/13` benign FPs, `13/13` attacks caught across Rounds 1 & 2).
>
> **Production Adaptation Note:** These blueprints use standard IANA/CERT IPFIX (`YAF` / `super_mediator`), ECS, and SIEM field placeholders. Further testing, schema alignment, and threshold tuning will be required for live or custom environments before promoting detections from shadow mode to alerting.

---

## 1. Environment Schema Adaptation Checklist

When adapting the blueprints below to live Spark SQL, SIEM, or data-lake tables:
1. Remap every placeholder table and column (e.g., `default_ipfix_flows`, `ssl_flows`, `http_flows`, `octetTotalCount`, `reverseOctetTotalCount`, `ja4`, `ja4x`, `sslServerName`, `silkAppLabel`) to exact target column names and data types (verifying timestamp units: seconds vs. milliseconds vs. microseconds).
2. Preserve all false-positive guardrails (authorized scanner IP/CIDR allowlist — never User-Agent trust; server/DMZ asset-tier joins instead of hostname prefixes; NAT-safe JA4 whiplash conditions; exclusion of static asset 404s, UUID 404s, and read-only `POST /search|/query`).
3. Pair every adapted query with a **Positive-Control Schema Check** (substituting a benign value such as `Chrome` or port `443`) to confirm rows return before running a 7-day shadow-mode dry run.
4. Maintain Risk-Based Alerting (RBA) tiers: **Tier A** (standalone alert), **Tier B** (behavioral corroborator requiring `>=2` signals or TI/asset multiplier), and **Tier C** (enrichment/hunt only).

---

## 2. Standard CERT NetSA YAF Bidirectional IPFIX Placeholder Schema Map

Replace the right-hand placeholders with your exact internal Spark SQL / SIEM column names:

| Logical Concept | Standard IANA / CERT IPFIX (`YAF` / `super_mediator`) | Internal Column Placeholder |
| :--- | :--- | :--- |
| Flow Start Time | `flowStartMicroseconds` (IE 152) / `flowStartMilliseconds` | `<TS_COL>` *(note unit: us / ms / timestamp)* |
| Source IP / Port | `sourceIPv4Address` (IE 8), `sourceTransportPort` (IE 7) | `<SRC_IP>`, `<SRC_PORT>` |
| Destination IP / Port | `destinationIPv4Address` (IE 12), `destinationTransportPort` (IE 11) | `<DST_IP>`, `<DST_PORT>` |
| Forward Bytes (Client → Server) | `octetTotalCount` (IE 85) | `<BYTES_OUT>` |
| Reverse Bytes (Server → Client) | `reverseOctetTotalCount` (PEN 29305) | `<BYTES_IN>` |
| Application DPI Label | `silkAppLabel` (CERT IE 33: `80`=HTTP, `443`=TLS, `53`=DNS) | `<APP_LABEL>` |
| TLS SNI / Host | `sslServerName` (CERT IE 294) / `httpHost` | `<SNI_OR_HOST>` |
| JA4 / JA4S / JA4H / JA4X | `ja4` (CERT IE 480), `ja4s`, `ja4h`, `ja4x` | `<JA4>`, `<JA4S>`, `<JA4H>`, `<JA4X>` |
| Legacy JA3 / JA3S | `sslClientJA3` (IE 463), `sslServerJA3S` (IE 465) | `<JA3>`, `<JA3S>` |
| HTTP Method / URI / Status / UA | `httpGet`, `httpResponse`, `httpUserAgent` | `<METHOD>`, `<URI>`, `<STATUS>`, `<UA>` |

---

## 3. Core Post-IOC Behavioral Hunt Blueprints (Spark SQL / Data-Lake SQL)

### Hunt 1 — Encrypted TLS 1.3 Sawtooth Growing-Context LLM Proxy (Zero-IOC, Pure Biflow)
*Catches self-hosted / VPS-proxied LLM API calls on TCP `443` with zero HTTP decryption, zero known domains, and zero User-Agent indicators.*
```sql
WITH ordered AS (
  SELECT
    <SRC_IP> AS src_ip,
    COALESCE(NULLIF(<SNI_OR_HOST>, ''), <DST_IP>) AS dst_target,
    <DST_IP> AS dst_ip,
    <TS_COL> AS ts,
    <BYTES_OUT> AS b_out,
    <BYTES_IN> AS b_in,
    <JA4> AS ja4,
    LAG(<BYTES_OUT>) OVER (PARTITION BY <SRC_IP>, COALESCE(NULLIF(<SNI_OR_HOST>, ''), <DST_IP>) ORDER BY <TS_COL>) AS prev_out,
    UNIX_TIMESTAMP(<TS_COL>) - UNIX_TIMESTAMP(
      LAG(<TS_COL>) OVER (PARTITION BY <SRC_IP>, COALESCE(NULLIF(<SNI_OR_HOST>, ''), <DST_IP>) ORDER BY <TS_COL>)
    ) AS dt_sec
  FROM <DEFAULT_IPFIX_TABLE>
  WHERE <DST_PORT> = 443
    AND <BYTES_IN> BETWEEN 300 AND 50000
    -- Join/exclude approved corporate AI gateways & CDN/SaaS allowlists here
),
turns AS (
  SELECT *,
    CASE WHEN prev_out IS NOT NULL AND (b_out - prev_out) >= 1500 AND dt_sec >= 3 THEN 1 ELSE 0 END AS is_growing_turn,
    CASE WHEN prev_out IS NOT NULL AND b_out <= prev_out * 0.6 THEN 1 ELSE 0 END AS is_compaction_drop
  FROM ordered
)
SELECT
  src_ip,
  dst_target,
  MAX(dst_ip) AS sample_dst_ip,
  MAX(ja4) AS sample_ja4,
  COUNT(*) AS flow_count,
  SUM(is_growing_turn) AS growing_turns,
  SUM(is_compaction_drop) AS compaction_drops,
  MIN(b_out) AS min_bytes_out,
  MAX(b_out) AS peak_bytes_out,
  ROUND(MAX(b_out) / GREATEST(MIN(b_out), 1), 2) AS growth_ratio
FROM turns
GROUP BY src_ip, dst_target, window(ts, '15 minutes', '5 minutes')
HAVING (growing_turns >= 4 AND peak_bytes_out >= 12000 AND growth_ratio >= 2.5)
    OR (growing_turns >= 5 AND compaction_drops >= 1 AND peak_bytes_out >= 10000)
ORDER BY growing_turns DESC, peak_bytes_out DESC;
```

### Hunt 2 — Port-Independent ARTEX Console/Proxy (`silkAppLabel`) & Raw-IP TLS (`ja4` = `t13i`/`t12i`)
```sql
SELECT
  <TS_COL> AS ts,
  <SRC_IP> AS src_ip,
  <DST_IP> AS dst_ip,
  <DST_PORT> AS dst_port,
  <APP_LABEL> AS app_label,
  <SNI_OR_HOST> AS sni,
  <JA4> AS ja4,
  split(<JA4>, '_')[0] AS ja4_a,
  split(<JA4>, '_')[1] AS ja4_b,
  <BYTES_OUT> AS bytes_out,
  <BYTES_IN> AS bytes_in
FROM <DEFAULT_IPFIX_TABLE>
WHERE (<APP_LABEL> IN (80, 443) AND <DST_PORT> IN (8787, 8788, 8790, 8890))
   OR (substring(<JA4>, 4, 1) = 'i' AND <DST_PORT> = 443 AND <BYTES_OUT> >= 12000)
ORDER BY ts DESC;
```

### Hunt 3 — NAT-Safe `JA4` / `JA4H` Client Stack Whiplash (Spoofed UA or Error/Edge Corroboration)
*Prevents false positives on shared corporate NAT gateways by requiring either identical spoofed User-Agent across `>=3` distinct TLS/HTTP client stacks OR `>=3` `4xx` errors / edge VPN URIs.*
```sql
SELECT
  <SRC_IP> AS src_ip,
  <SNI_OR_HOST> AS target_host,
  COUNT(*) AS reqs,
  COUNT(DISTINCT <JA4>) AS distinct_ja4,
  COUNT(DISTINCT split(<JA4>, '_')[0] || '_' || split(<JA4>, '_')[1]) AS distinct_ja4_ab,
  COUNT(DISTINCT <JA4H>) AS distinct_ja4h,
  COUNT(DISTINCT <UA>) AS distinct_uas,
  SUM(CASE WHEN <STATUS> >= 400 THEN 1 ELSE 0 END) AS err_4xx_5xx
FROM <HTTP_SSL_JOINED_TABLE>
WHERE <SRC_IP> NOT IN (SELECT ip FROM <AUTHORIZED_SCANNER_ALLOWLIST>)
GROUP BY <SRC_IP>, <SNI_OR_HOST>, window(<TS_COL>, '10 minutes')
HAVING (distinct_ja4_ab >= 3 OR distinct_ja4h >= 3)
   AND (distinct_uas <= 1 OR err_4xx_5xx >= 3)
ORDER BY distinct_ja4_ab DESC, err_4xx_5xx DESC;
```

### Hunt 4 — `JA4X_c` + `JA4S` + Team Cymru ASN Infrastructure Clustering (Eliminating `a`/`b` Collisions)
*Suppresses the top ~25 public-CA `JA4X` hashes (`Let's Encrypt`, `DigiCert`, `Google Trust Services`, `Sectigo`, etc.) and clusters self-signed/bespoke tool certs (`ja4x_a == ja4x_b`) by extension-order fingerprint (`ja4x_c`) + server TLS stack (`ja4s`).*
```sql
WITH top_public_cas AS (
  SELECT <JA4X> AS ja4x
  FROM <SSL_FLOWS_TABLE>
  WHERE <TS_COL> >= current_timestamp() - INTERVAL 14 DAYS
    AND <JA4X> IS NOT NULL
  GROUP BY <JA4X>
  ORDER BY COUNT(DISTINCT <DST_IP>) DESC
  LIMIT 25
),
filtered_ssl AS (
  SELECT
    <DST_IP> AS dst_ip,
    <DST_PORT> AS dst_port,
    <SNI_OR_HOST> AS sni,
    <JA4X> AS ja4x,
    split(<JA4X>, '_')[0] AS ja4x_a,
    split(<JA4X>, '_')[1] AS ja4x_b,
    split(<JA4X>, '_')[2] AS ja4x_c,
    <JA4S> AS ja4s
  FROM <SSL_FLOWS_TABLE>
  WHERE <TS_COL> >= current_timestamp() - INTERVAL 24 HOURS
    AND <JA4X> IS NOT NULL
    AND <JA4X> NOT IN (SELECT ja4x FROM top_public_cas)
)
SELECT
  s.ja4x_c,
  s.ja4s,
  (s.ja4x_a = s.ja4x_b) AS is_self_signed_structure,
  c.asn,
  c.as_org,
  COUNT(DISTINCT s.dst_ip) AS distinct_dst_ips,
  COLLECT_SET(s.dst_port) AS ports,
  SLICE(COLLECT_SET(s.sni), 1, 10) AS sample_snis
FROM filtered_ssl s
LEFT JOIN <TEAM_CYMRU_DELTA_CACHE> c ON s.dst_ip = c.ip
WHERE (s.ja4x_a = s.ja4x_b) OR s.dst_port IN (8787, 8788, 8790, 8890, 8080, 8090, 8443)
-- Tip (Hunt.io 38.244.50[.]120 + 19 ARTEX consoles): also pivot SSL certs with Issuer Organization = 'ARTEX' (10-year self-signed, CN=<IP>)!
GROUP BY s.ja4x_c, s.ja4s, (s.ja4x_a = s.ja4x_b), c.asn, c.as_org
ORDER BY distinct_dst_ips DESC;
```

### Hunt 5 — Team Cymru API Delta Cache Pattern (Minimize API Quota Burn)
1. Extract distinct external candidate IPs (`candidate_ips`) from Hunts 1–4.
2. `LEFT ANTI JOIN` against `<TEAM_CYMRU_DELTA_CACHE>` where `enriched_at >= current_timestamp() - INTERVAL 72 HOURS`.
3. Query Team Cymru API **only** for the uncached delta IPs, `MERGE INTO <TEAM_CYMRU_DELTA_CACHE>` (`ip`, `asn`, `as_org`, `country`, `tags`, `enriched_at`).
4. Apply an RBA risk multiplier (`+20 pts`) when candidate flows hit commercial VPS / bulletproof hosting / proxy-exit ASNs or co-occur with ports `8787`/`8788`/`8790`/`8080`.

---

## 4. Production FP & Anti-Echo-Chamber Guardrails (Mandatory During Adaptation)
1. **Never allowlist scanners by `User-Agent`** (`QualysGuard/1.0`, `Nessus`, etc.) — allowlist strictly by **CMDB/network scanner IP/CIDR**.
2. **Never rely on hostname prefixes alone (`WKSTN-*`, `LAPTOP-*`)** for LLM API tiering when you have an EDR/CMDB device-role table (`device_type == 'server'` / DMZ VLAN / non-interactive service account).
3. **Exclude read-only POST endpoints** (`/search`, `/query`, `/filter`, `/graphql`) and **static browser asset `404`s** (`/favicon.ico`, `/robots.txt`, `.png`, `.css.map`) from Write→Readback verification rules.
4. **Separate `java` / `node` from true web daemons** (`w3wp.exe`, `nginx`, `httpd`, `php-fpm`, `restjavad`): require recon/download/encoded args on `java`/`node` child shells.
5. **Run Positive-Control Schema Checks + 7-Day Shadow Mode** (see `docs/soc_siem_validation_playbook.md`) before enabling any rule for paging.
6. **Keep Risk-Based Alerting (RBA) tiers:**
   - **Tier A (`>=70`, Alert):** Known ARTEX/BLOODALCHEMY/console artifacts, `w3wp/nginx -> shell`, SSRF + upload webshell, Entra SP fail→success→Key Vault/SAS, AD Kerberoast/DCSync/`vshell`/`AdaptixC2`/`WISP`, multi-account spray (`>=8` distinct users), sawtooth LLM relay (`>=4` turns, `>=12KB`, `>=2.5x`).
   - **Tier B (`45–69`, Corroborate/Hunt):** Single behavioral signals (`ja4_client_stack_whiplash`, `llm_cli_context_idioms`, `multi_worker_redundant_recon`, `think_act_bimodal_cadence`).
   - **Tier C (`<45`, Context/Enrichment Only):** Standalone volumetric bursts, workstation LLM egress, standalone `:8080`, perishable campaign IPs (`38.244.50[.]120`, `144.172.64[.]60`, `144.172.64[.]99`, `144.172.64[.]128`, `89.46.234[.]50`, `sqlserver-sqlite[.]com`).
