# Databricks notebook source
# MAGIC %md
# MAGIC # 00 — Databricks Free Edition Demo Seeder (`workspace.default.artex_*`)
# MAGIC
# MAGIC > **Purpose:** Populates 6 Unity Catalog managed Delta tables in your **Databricks Free Edition** sandbox (`workspace.default.artex_*`) with 100% synthetic RFC 5737 attack + benign telemetry spanning the **last 72 hours**, ready for:
# MAGIC > 1. All **11 read-only hunts** in `artex_behavioral_hunt_dashboard.py` (`11/11` caught, `0` benign FPs), and
# MAGIC > 2. Rich time-series charts, RBA score distributions, and drill-downs in **`artex_lakeview_dashboard.lvdash.json`** (Databricks AI/BI Dashboards).
# MAGIC >
# MAGIC > **Why a Separate Notebook?** Keeping table seeding isolated here guarantees `artex_behavioral_hunt_dashboard.py` stays **100% strictly read-only** (`SELECT` / CTEs only) when promoted to a read-only enterprise workspace.

# COMMAND ----------

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone
from typing import Any


def generate_demo_datasets(
    scale: str = "dashboard",
    anchor_ts: datetime | None = None,
) -> dict[str, list[tuple[Any, ...]]]:
    """Generate deterministic synthetic RFC 5737 attack + realistic benign telemetry across 6 tables.

    Args:
        scale: "dashboard" (~3,400 rows across 72h for realistic AI/BI charts) or "smoke" (~75 rows).
        anchor_ts: Naive UTC anchor timestamp (defaults to current UTC time rounded to seconds).
    """
    rng = random.Random(42)
    now = (anchor_ts or datetime.now(timezone.utc)).replace(tzinfo=None, microsecond=0)

    def _ago(hours: float = 0.0, minutes: float = 0.0, seconds: float = 0.0) -> datetime:
        return now - timedelta(hours=hours, minutes=minutes, seconds=seconds)

    # ------------------------------------------------------------------
    # 1. artex_ipfix_flows (Hunts 1, 2, 5, 7 + 72h realistic benign traffic)
    # ------------------------------------------------------------------
    ipfix_rows: list[tuple[Any, ...]] = [
        # Attack 1: Encrypted TLS 1.3 Sawtooth growing-context LLM proxy (0 IOCs, port 443)
        (_ago(hours=6, minutes=10, seconds=0), "10.20.30.40", "198.51.100.244", 443, 4200, 1800, 443, "relay-01.example-vps.net", "t13d1516h2_8daaf6152771_b186095e22b6"),
        (_ago(hours=6, minutes=9, seconds=42), "10.20.30.40", "198.51.100.244", 443, 9800, 2100, 443, "relay-01.example-vps.net", "t13d1516h2_8daaf6152771_b186095e22b6"),
        (_ago(hours=6, minutes=9, seconds=21), "10.20.30.40", "198.51.100.244", 443, 17400, 1950, 443, "relay-01.example-vps.net", "t13d1516h2_8daaf6152771_b186095e22b6"),
        (_ago(hours=6, minutes=8, seconds=58), "10.20.30.40", "198.51.100.244", 443, 28900, 2300, 443, "relay-01.example-vps.net", "t13d1516h2_8daaf6152771_b186095e22b6"),
        (_ago(hours=6, minutes=8, seconds=32), "10.20.30.40", "198.51.100.244", 443, 44100, 2400, 443, "relay-01.example-vps.net", "t13d1516h2_8daaf6152771_b186095e22b6"),
        (_ago(hours=6, minutes=8, seconds=4), "10.20.30.40", "198.51.100.244", 443, 61200, 2650, 443, "relay-01.example-vps.net", "t13d1516h2_8daaf6152771_b186095e22b6"),
        # Attack 2: Port-independent ARTEX console (:8787) + Raw-IP TLS (ja4 pos 4 = 'i')
        (_ago(hours=5, minutes=30), "10.20.30.41", "203.0.113.120", 8787, 3500, 6200, 80, "", "t13i1516h2_000011112222_333344445555"),
        (_ago(hours=5, minutes=29, seconds=50), "10.20.30.41", "203.0.113.121", 443, 22500, 3100, 443, "", "t13i1516h2_aaaa11112222_333344445555"),
        # Attack 5: Compromised web server 10.50.1.10 calling back to probing IP 203.0.113.88 on :8443
        (_ago(hours=4, minutes=19, seconds=35), "10.50.1.10", "203.0.113.88", 8443, 6400, 1200, 443, "", "t13i1516h2_111122223333_444455556666"),
        # Attack 7: Compromised app server 10.50.2.15 sweeping 5 internal hosts on SMB/WinRM in 12s
        (_ago(hours=3, minutes=15, seconds=12), "10.50.2.15", "10.50.9.11", 5985, 1400, 900, 0, "", ""),
        (_ago(hours=3, minutes=15, seconds=9), "10.50.2.15", "10.50.9.12", 445, 1400, 900, 0, "", ""),
        (_ago(hours=3, minutes=15, seconds=6), "10.50.2.15", "10.50.9.13", 5985, 1400, 900, 0, "", ""),
        (_ago(hours=3, minutes=15, seconds=3), "10.50.2.15", "10.50.9.14", 445, 1400, 900, 0, "", ""),
        (_ago(hours=3, minutes=15, seconds=0), "10.50.2.15", "10.50.9.15", 5985, 1400, 900, 0, "", ""),
        # Core benign baselines (steady S3 uploads + 2-host SMB backup)
        (_ago(hours=6, minutes=10), "10.90.1.5", "198.51.100.10", 443, 250000, 450, 443, "s3.amazonaws.com", "t13d1516h2_8daaf6152771_b186095e22b6"),
        (_ago(hours=6, minutes=9, seconds=50), "10.90.1.5", "198.51.100.10", 443, 249800, 460, 443, "s3.amazonaws.com", "t13d1516h2_8daaf6152771_b186095e22b6"),
        (_ago(hours=6, minutes=9, seconds=40), "10.90.1.5", "198.51.100.10", 443, 250100, 440, 443, "s3.amazonaws.com", "t13d1516h2_8daaf6152771_b186095e22b6"),
        (_ago(hours=5, minutes=40), "10.90.1.8", "10.50.9.20", 445, 85000, 1200, 0, "", ""),
        (_ago(hours=5, minutes=39, seconds=30), "10.90.1.8", "10.50.9.21", 445, 84000, 1100, 0, "", ""),
    ]

    if scale == "dashboard":
        benign_snis = [
            ("198.51.100.10", "s3.amazonaws.com"),
            ("198.51.100.11", "api.github.example"),
            ("198.51.100.12", "cdn.cloudflare.example"),
            ("198.51.100.13", "login.microsoftonline.example"),
            ("198.51.100.14", "packages.ubuntu.example"),
            ("198.51.100.15", "telemetry.datadog.example"),
        ]
        benign_srcs = [f"10.90.1.{i}" for i in range(20, 45)]
        for hr in range(72):
            for _ in range(16):
                src = rng.choice(benign_srcs)
                dst_ip, sni = rng.choice(benign_snis)
                ts = _ago(hours=hr, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59))
                # Steady/small HTTPS traffic (kept <= 4800 bytes_out so Sawtooth peak >= 12000B never FPs)
                b_out = rng.randint(1200, 4800)
                b_in = rng.randint(800, 28000)
                ipfix_rows.append((ts, src, dst_ip, 443, b_out, b_in, 443, sni, "t13d1516h2_8daaf6152771_e5627efa2ab1"))

    # ------------------------------------------------------------------
    # 2. artex_ssl_flows (Hunt 4 + benign public-CA TLS handshakes)
    # ------------------------------------------------------------------
    ssl_rows: list[tuple[Any, ...]] = [
        # Attack 4: Self-signed bespoke cert cluster (ja4x_a == ja4x_b) across 2 operator consoles
        (_ago(hours=5, minutes=30), "10.20.30.41", "203.0.113.120", 8787, "", "t130200_1301_a56c5b993250", "7022c563de38_7022c563de38_e7b1c49d2a10"),
        (_ago(hours=5, minutes=20), "10.20.30.42", "203.0.113.122", 8090, "", "t130200_1301_a56c5b993250", "7022c563de38_7022c563de38_e7b1c49d2a10"),
        (_ago(hours=5, minutes=10), "10.20.30.43", "203.0.113.123", 8787, "", "t130200_1301_a56c5b993250", "7022c563de38_7022c563de38_e7b1c49d2a10"),
        # Benign public-CA cert
        (_ago(hours=6, minutes=10), "10.90.1.5", "198.51.100.10", 443, "s3.amazonaws.com", "t130200_1301_234abc", "2bab15409345_552211009988_112233445566"),
    ]
    if scale == "dashboard":
        public_cas = [
            ("2bab15409345_552211009988_112233445566", "t130200_1301_234abc", "s3.amazonaws.com"),
            ("9911aabbccdd_001122334455_aabbccddeeff", "t130200_1302_778899", "api.github.example"),
            ("4433221100ff_6677889900aa_ccddeeff0011", "t130200_1301_334455", "cdn.cloudflare.example"),
        ]
        for hr in range(72):
            for _ in range(5):
                ja4x, ja4s, sni = rng.choice(public_cas)
                ssl_rows.append((
                    _ago(hours=hr, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59)),
                    f"10.90.1.{rng.randint(20, 44)}",
                    f"198.51.100.{rng.randint(10, 15)}",
                    443,
                    sni,
                    ja4s,
                    ja4x,
                ))

    # ------------------------------------------------------------------
    # 3. artex_http_flows (Hunts 3, 5, 6, 8, 9 + realistic benign web traffic)
    # ------------------------------------------------------------------
    http_rows: list[tuple[Any, ...]] = [
        # Attack 3: Spoofed identical UA cycling 3 distinct JA4/JA4H stacks with 403/404/401
        (_ago(hours=4, minutes=40, seconds=8), "203.0.113.77", "10.50.1.10", 443, "portal.corp.local", "GET", "/api/v1/admin", 403, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_aaa111_bbb111", "ge11cn200000_111_000_000", 420),
        (_ago(hours=4, minutes=40, seconds=4), "203.0.113.77", "10.50.1.10", 443, "portal.corp.local", "GET", "/api/v1/users", 404, "Mozilla/5.0 Chrome/131.0", "t13d190900_ccc222_ddd222", "ge11nn040000_222_000_000", 430),
        (_ago(hours=4, minutes=40, seconds=0), "203.0.113.77", "10.50.1.10", 443, "portal.corp.local", "POST", "/api/v1/export", 401, "Mozilla/5.0 Chrome/131.0", "t12d080800_eee333_fff333", "po11nn030000_333_000_000", 440),
        # Attack 5 trigger: External IP 203.0.113.88 probes web server 10.50.1.10 (25s before callback)
        (_ago(hours=4, minutes=20, seconds=0), "203.0.113.88", "10.50.1.10", 443, "portal.corp.local", "POST", "/api/render", 200, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "po11cn14enus_444_000_000", 600),
        # Attack 6 trigger: External IP 203.0.113.99 probes web server 10.50.1.11 (14s before OOB DNS)
        (_ago(hours=3, minutes=45, seconds=14), "203.0.113.99", "10.50.1.11", 443, "api.corp.local", "POST", "/v2/import", 200, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "po11cn14enus_555_000_000", 620),
        # Attack 8: Recording-Proxy Collapse (1 JA4 from mitmproxy, 3 JA4Hs, 3 UA families, 3x 4xx)
        (_ago(hours=2, minutes=30, seconds=6), "203.0.113.150", "10.50.1.12", 443, "app.corp.local", "GET", "/api/v1/secrets", 403, "curl/8.5.0", "t13d1311h2_f57a46bbacb6_e7c285222651", "ge11nn030000_fe444ad14866_000000000000_000000000000", 210),
        (_ago(hours=2, minutes=30, seconds=3), "203.0.113.150", "10.50.1.12", 443, "app.corp.local", "GET", "/api/v1/tokens", 404, "python-httpx/0.28.1", "t13d1311h2_f57a46bbacb6_e7c285222651", "ge11nn050000_be0d0b335e46_000000000000_000000000000", 240),
        (_ago(hours=2, minutes=30, seconds=0), "203.0.113.150", "10.50.1.12", 443, "app.corp.local", "GET", "/_i6084_probe_missing", 404, "Go-http-client/1.1", "t13d1311h2_f57a46bbacb6_e7c285222651", "ge11nn030000_cd680697de12_000000000000_000000000000", 220),
        # Attack 9: Ruby2Shell Zero-IOC monotonic 500/502 heap-grooming ramp + 200 recovery
        (_ago(hours=2, minutes=10, seconds=3), "198.51.100.160", "10.50.1.15", 443, "rails.corp.local", "POST", "/api/v1/rails-form", 502, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "po11cn14enus_999_000_000", 64),
        (_ago(hours=2, minutes=10, seconds=2), "198.51.100.160", "10.50.1.15", 443, "rails.corp.local", "POST", "/api/v1/rails-form", 502, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "po11cn14enus_999_000_000", 128),
        (_ago(hours=2, minutes=10, seconds=1), "198.51.100.160", "10.50.1.15", 443, "rails.corp.local", "POST", "/api/v1/rails-form", 500, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "po11cn14enus_999_000_000", 256),
        (_ago(hours=2, minutes=10, seconds=0), "198.51.100.160", "10.50.1.15", 443, "rails.corp.local", "POST", "/api/v1/rails-form", 200, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "po11cn14enus_999_000_000", 384),
        # Benign Baselines: Allowlisted scanner + real Chrome + honest curl + random-size 503 blip
        (_ago(hours=4, minutes=30, seconds=2), "198.51.100.250", "10.50.1.10", 443, "portal.corp.local", "GET", "/test1", 404, "QualysGuard", "t13d111_1_1", "ge11_1_0_0", 180),
        (_ago(hours=4, minutes=30, seconds=1), "198.51.100.250", "10.50.1.10", 443, "portal.corp.local", "GET", "/test2", 404, "QualysGuard", "t13d222_2_2", "ge11_2_0_0", 180),
        (_ago(hours=4, minutes=30, seconds=0), "198.51.100.250", "10.50.1.10", 443, "portal.corp.local", "GET", "/test3", 404, "QualysGuard", "t13d333_3_3", "ge11_3_0_0", 180),
        (_ago(hours=2, minutes=5), "198.51.100.210", "10.50.1.15", 443, "rails.corp.local", "GET", "/dashboard", 200, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "ge11cn14enus_60a1_000_000", 320),
        (_ago(hours=2, minutes=4), "198.51.100.211", "10.50.1.15", 443, "rails.corp.local", "GET", "/healthz", 200, "curl/8.5.0", "t13d1311h2_f57a46_e7c285", "ge11nn030000_fe44_000_000", 120),
        (_ago(hours=2, minutes=3, seconds=4), "198.51.100.212", "10.50.1.15", 443, "rails.corp.local", "POST", "/api/v1/orders", 503, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "po11cn14enus_60a1_000_000", 512),
        (_ago(hours=2, minutes=3, seconds=2), "198.51.100.212", "10.50.1.15", 443, "rails.corp.local", "POST", "/api/v1/orders", 503, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "po11cn14enus_60a1_000_000", 190),
        (_ago(hours=2, minutes=3, seconds=0), "198.51.100.212", "10.50.1.15", 443, "rails.corp.local", "POST", "/api/v1/orders", 503, "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "po11cn14enus_60a1_000_000", 410),
    ]
    if scale == "dashboard":
        benign_clients = [
            ("198.51.100.220", "Mozilla/5.0 Chrome/131.0", "t13d1516h2_8daaf6_b18609", "ge11cn14enus_60a1_000_000"),
            ("198.51.100.221", "Mozilla/5.0 Firefox/132.0", "t13d1715h2_5b5761_5c2c66", "ge11cn13enus_a1b2_000_000"),
            ("198.51.100.222", "Mozilla/5.0 Safari/605.1.15", "t13d2014h2_a09f3c_14788d", "ge11cn11enus_c3d4_000_000"),
            ("198.51.100.223", "curl/8.5.0", "t13d1311h2_f57a46_e7c285", "ge11nn030000_fe44_000_000"),
        ]
        benign_paths = ["/dashboard", "/api/v1/status", "/api/v1/jobs", "/healthz", "/docs", "/login"]
        for hr in range(72):
            for _ in range(12):
                src, ua, ja4, ja4h = rng.choice(benign_clients)
                status = 200 if rng.random() < 0.94 else 304
                http_rows.append((
                    _ago(hours=hr, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59)),
                    src,
                    "10.50.1.15",
                    443,
                    "rails.corp.local",
                    "GET",
                    rng.choice(benign_paths),
                    status,
                    ua,
                    ja4,
                    ja4h,
                    rng.randint(180, 950),
                ))

    # ------------------------------------------------------------------
    # 4. artex_dns_flows (Hunt 6 + benign DNS baselines)
    # ------------------------------------------------------------------
    dns_rows: list[tuple[Any, ...]] = [
        # Attack 6: High-entropy hex-prefixed OOB DNS lookup 14s after probe from 10.50.1.11
        (_ago(hours=3, minutes=45, seconds=0), "10.50.1.11", "10.50.0.53", 53, "f4a8c19e02b7d3.oob-collector.example"),
        # Benign baselines
        (_ago(hours=3, minutes=45, seconds=4), "10.50.1.11", "10.50.0.53", 53, "d111111abcdef8.cloudfront.net"),
        (_ago(hours=3, minutes=45, seconds=2), "10.50.1.11", "10.50.0.53", 53, "api.stripe.example"),
    ]
    if scale == "dashboard":
        benign_fqdns = [
            "d111111abcdef8.cloudfront.net",
            "api.stripe.example",
            "s3.amazonaws.com",
            "login.microsoftonline.com",
            "github.com",
            "pypi.org",
            "app.corp.local",
        ]
        for hr in range(72):
            for _ in range(7):
                dns_rows.append((
                    _ago(hours=hr, minutes=rng.randint(0, 59), seconds=rng.randint(0, 59)),
                    f"10.50.1.{rng.randint(10, 18)}",
                    "10.50.0.53",
                    53,
                    rng.choice(benign_fqdns),
                ))

    # ------------------------------------------------------------------
    # 5. artex_entra_sp_logs (Hunt 10 + benign SaaS backup & worker SPs)
    # ------------------------------------------------------------------
    entra_rows: list[tuple[Any, ...]] = [
        # Attack 10: Zero-401 stolen SP replayed across 3 external /16 prefixes + 4 M365/Vault resources
        (_ago(hours=1, minutes=50), "198.51.100.51", "Backup-Connector-SP", "Microsoft Graph", "0"),
        (_ago(hours=1, minutes=48), "203.0.113.52", "Backup-Connector-SP", "Office 365 Exchange Online", "0"),
        (_ago(hours=1, minutes=46), "192.0.2.53", "Backup-Connector-SP", "Office 365 SharePoint Online", "0"),
        (_ago(hours=1, minutes=44), "192.0.2.54", "Backup-Connector-SP", "Azure Key Vault", "0"),
        # Core benign baselines
        (_ago(hours=1, minutes=40, seconds=15), "203.0.113.200", "Veeam-O365-Backup-SP", "Microsoft Graph", "0"),
        (_ago(hours=1, minutes=40, seconds=10), "203.0.113.200", "Veeam-O365-Backup-SP", "Office 365 Exchange Online", "0"),
        (_ago(hours=1, minutes=40, seconds=5), "203.0.113.200", "Veeam-O365-Backup-SP", "Office 365 SharePoint Online", "0"),
        (_ago(hours=1, minutes=40, seconds=0), "203.0.113.200", "Veeam-O365-Backup-SP", "Microsoft Teams Services", "0"),
        (_ago(hours=1, minutes=35, seconds=20), "198.51.1.10", "Same16-Worker-SP", "Microsoft Graph", "0"),
        (_ago(hours=1, minutes=35, seconds=10), "198.51.2.10", "Same16-Worker-SP", "Office 365 Exchange Online", "0"),
        (_ago(hours=1, minutes=35, seconds=0), "198.51.3.10", "Same16-Worker-SP", "Office 365 SharePoint Online", "0"),
        (_ago(hours=1, minutes=30, seconds=10), "10.50.0.10", "Internal-Sync-SP", "Microsoft Graph", "0"),
        (_ago(hours=1, minutes=30, seconds=5), "10.51.0.11", "Internal-Sync-SP", "Office 365 Exchange Online", "0"),
        (_ago(hours=1, minutes=30, seconds=0), "10.52.0.12", "Internal-Sync-SP", "Azure Key Vault", "0"),
    ]
    if scale == "dashboard":
        for hr in range(72):
            entra_rows.append((_ago(hours=hr, minutes=10), "203.0.113.200", "Veeam-O365-Backup-SP", "Office 365 Exchange Online", "0"))
            entra_rows.append((_ago(hours=hr, minutes=25), f"198.51.{rng.randint(1, 3)}.10", "Same16-Worker-SP", "Microsoft Graph", "0"))
            entra_rows.append((_ago(hours=hr, minutes=40), f"10.50.0.{rng.randint(10, 20)}", "Internal-Sync-SP", "Microsoft Graph", "0"))

    # ------------------------------------------------------------------
    # 6. artex_gcp_audit_logs (Hunt 11 + benign Terraform/platform/human/app SA)
    # ------------------------------------------------------------------
    gcp_rows: list[tuple[Any, ...]] = [
        # Attack 11: Single external IP operating 3 distinct SAs + PERMISSION_DENIED -> AccessSecretVersion
        (_ago(hours=1, minutes=10, seconds=60), "198.51.100.77", "ci-worker-01@prod-proj.iam.gserviceaccount.com", "storage.googleapis.com", "storage.buckets.list", "projects/prod-proj", 7),
        (_ago(hours=1, minutes=10, seconds=58), "198.51.100.77", "ci-worker-01@prod-proj.iam.gserviceaccount.com", "compute.googleapis.com", "v1.compute.instances.list", "projects/prod-proj", 7),
        (_ago(hours=1, minutes=10, seconds=56), "198.51.100.77", "ci-worker-01@prod-proj.iam.gserviceaccount.com", "iam.googleapis.com", "google.iam.admin.v1.ListServiceAccounts", "projects/prod-proj", 7),
        (_ago(hours=1, minutes=10, seconds=54), "198.51.100.77", "ci-worker-01@prod-proj.iam.gserviceaccount.com", "secretmanager.googleapis.com", "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion", "projects/123/secrets/prod-key/versions/latest", 0),
        (_ago(hours=1, minutes=10, seconds=30), "198.51.100.77", "deploy-bot-02@prod-proj.iam.gserviceaccount.com", "cloudresourcemanager.googleapis.com", "GetIamPolicy", "projects/prod-proj", 7),
        (_ago(hours=1, minutes=10, seconds=0), "198.51.100.77", "1234567890-compute@developer.gserviceaccount.com", "iamcredentials.googleapis.com", "GenerateAccessToken", "projects/prod-proj", 0),
        # Core benign baselines
        (_ago(hours=1, minutes=5, seconds=6), "198.51.100.120", "terraform-deploy@prod-proj.iam.gserviceaccount.com", "iam.googleapis.com", "SetIamPolicy", "projects/prod-proj", 0),
        (_ago(hours=1, minutes=5, seconds=4), "198.51.100.120", "service-123@gcp-sa-gke.iam.gserviceaccount.com", "compute.googleapis.com", "v1.compute.instances.list", "projects/prod-proj", 0),
        (_ago(hours=1, minutes=5, seconds=2), "198.51.100.120", "123@cloudservices.gserviceaccount.com", "compute.googleapis.com", "v1.compute.instances.list", "projects/prod-proj", 0),
        (_ago(hours=1, minutes=5, seconds=0), "198.51.100.120", "gke-system@prod-proj.iam.gserviceaccount.com", "container.googleapis.com", "GetCluster", "projects/prod-proj", 0),
        (_ago(hours=1, minutes=4, seconds=10), "198.51.100.200", "alice@corp.example", "compute.googleapis.com", "v1.compute.instances.list", "projects/prod-proj", 0),
        (_ago(hours=1, minutes=4, seconds=5), "198.51.100.200", "bob@corp.example", "storage.googleapis.com", "storage.buckets.list", "projects/prod-proj", 0),
        (_ago(hours=1, minutes=4, seconds=0), "198.51.100.200", "carol@corp.example", "bigquery.googleapis.com", "jobservice.list", "projects/prod-proj", 0),
        (_ago(hours=1, minutes=2, seconds=1), "203.0.113.15", "app-backend@prod-proj.iam.gserviceaccount.com", "secretmanager.googleapis.com", "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion", "projects/123/secrets/db-pass/versions/latest", 0),
        (_ago(hours=1, minutes=2, seconds=0), "203.0.113.15", "app-backend@prod-proj.iam.gserviceaccount.com", "secretmanager.googleapis.com", "google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion", "projects/123/secrets/stripe-key/versions/latest", 0),
    ]
    if scale == "dashboard":
        for hr in range(72):
            gcp_rows.append((_ago(hours=hr, minutes=12), "198.51.100.120", "terraform-deploy@prod-proj.iam.gserviceaccount.com", "compute.googleapis.com", "v1.compute.instances.list", "projects/prod-proj", 0))
            gcp_rows.append((_ago(hours=hr, minutes=24), "198.51.100.200", rng.choice(["alice@corp.example", "bob@corp.example", "carol@corp.example"]), "storage.googleapis.com", "storage.objects.get", "projects/prod-proj", 0))
            gcp_rows.append((_ago(hours=hr, minutes=36), "203.0.113.15", "app-backend@prod-proj.iam.gserviceaccount.com", "storage.googleapis.com", "storage.objects.get", "projects/prod/buckets/arm-compute-container-iam-storage-logs/objects/app.json", 0))

    return {
        "artex_ipfix_flows": ipfix_rows,
        "artex_ssl_flows": ssl_rows,
        "artex_http_flows": http_rows,
        "artex_dns_flows": dns_rows,
        "artex_entra_sp_logs": entra_rows,
        "artex_gcp_audit_logs": gcp_rows,
    }


# COMMAND ----------

if "spark" in globals() and "dbutils" in globals():
    from pyspark.sql.types import (
        IntegerType,
        LongType,
        StringType,
        StructField,
        StructType,
        TimestampType,
    )

    dbutils.widgets.text("target_schema", "workspace.default")  # type: ignore[name-defined]
    dbutils.widgets.dropdown("demo_scale", "dashboard", ["dashboard", "smoke"])  # type: ignore[name-defined]
    TARGET_SCHEMA = dbutils.widgets.get("target_schema").strip() or "workspace.default"  # type: ignore[name-defined]
    DEMO_SCALE = dbutils.widgets.get("demo_scale").strip() or "dashboard"  # type: ignore[name-defined]

    datasets = generate_demo_datasets(scale=DEMO_SCALE)

    schemas = {
        "artex_ipfix_flows": StructType([
            StructField("flow_ts", TimestampType(), False),
            StructField("src_ip", StringType(), False),
            StructField("dst_ip", StringType(), False),
            StructField("dst_port", IntegerType(), False),
            StructField("octetTotalCount", LongType(), False),
            StructField("reverseOctetTotalCount", LongType(), False),
            StructField("silkAppLabel", IntegerType(), False),
            StructField("sslServerName", StringType(), True),
            StructField("ja4", StringType(), True),
        ]),
        "artex_ssl_flows": StructType([
            StructField("flow_ts", TimestampType(), False),
            StructField("src_ip", StringType(), False),
            StructField("dst_ip", StringType(), False),
            StructField("dst_port", IntegerType(), False),
            StructField("sslServerName", StringType(), True),
            StructField("ja4s", StringType(), True),
            StructField("ja4x", StringType(), True),
        ]),
        "artex_http_flows": StructType([
            StructField("flow_ts", TimestampType(), False),
            StructField("src_ip", StringType(), False),
            StructField("dst_ip", StringType(), False),
            StructField("dst_port", IntegerType(), False),
            StructField("sslServerName", StringType(), True),
            StructField("http_method", StringType(), True),
            StructField("http_path", StringType(), True),
            StructField("http_status", IntegerType(), True),
            StructField("http_ua", StringType(), True),
            StructField("ja4", StringType(), True),
            StructField("ja4h", StringType(), True),
            StructField("bytes_out", LongType(), True),
        ]),
        "artex_dns_flows": StructType([
            StructField("flow_ts", TimestampType(), False),
            StructField("src_ip", StringType(), False),
            StructField("dst_ip", StringType(), False),
            StructField("dst_port", IntegerType(), False),
            StructField("dns_query", StringType(), False),
        ]),
        "artex_entra_sp_logs": StructType([
            StructField("created_ts", TimestampType(), False),
            StructField("ip_address", StringType(), False),
            StructField("service_principal_name", StringType(), False),
            StructField("resource_display_name", StringType(), False),
            StructField("result_type", StringType(), False),
        ]),
        "artex_gcp_audit_logs": StructType([
            StructField("event_ts", TimestampType(), False),
            StructField("caller_ip", StringType(), False),
            StructField("principal_email", StringType(), False),
            StructField("service_name", StringType(), False),
            StructField("method_name", StringType(), False),
            StructField("resource_name", StringType(), False),
            StructField("grpc_code", IntegerType(), False),
        ]),
    }

    total_rows = 0
    for table_short, rows in datasets.items():
        full_name = f"{TARGET_SCHEMA}.{table_short}"
        df = spark.createDataFrame(rows, schema=schemas[table_short])  # type: ignore[name-defined]
        df.write.format("delta").mode("overwrite").option("overwriteSchema", "true").saveAsTable(full_name)
        cnt = spark.table(full_name).count()  # type: ignore[name-defined]
        total_rows += cnt
        print(f"Seeded {full_name}: {cnt} rows")

    print(f"\nDone! Seeded {total_rows} synthetic rows across 6 Delta tables in `{TARGET_SCHEMA}` (scale={DEMO_SCALE}).")
    print("Next: import `artex_lakeview_dashboard.lvdash.json` under Dashboards -> Import, or run `artex_behavioral_hunt_dashboard.py`!")
