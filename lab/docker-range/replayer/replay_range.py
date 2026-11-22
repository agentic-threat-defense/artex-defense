"""100% harmless behavioral traffic replayer for air-gapped Docker Purple-Team Range.

Generates ONLY benign HTTP/TLS wire traffic against the local isolated mock target (172.30.0.20)
to exercise real Suricata 7, real Zeek LTS, and real Nginx -> `artex-hunt scan` pipelines.
Zero exploit payloads, zero offensive frameworks, zero external connections.
"""

from __future__ import annotations

import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

TARGET_IP = "172.30.0.20"


def http_req(
    path: str,
    *,
    method: str = "GET",
    port: int = 80,
    ua: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
) -> int:
    url = f"http://{TARGET_IP}:{port}{path}"
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("User-Agent", ua)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            resp.read()
            return int(resp.status)
    except urllib.error.HTTPError as exc:
        exc.read()
        return int(exc.code)


def tls_req_with_sni(
    sni: str,
    path: str = "/sync",
    body_bytes: int = 0,
    *,
    force_tls12: bool = False,
) -> None:
    """Open a real TLS connection to the LOCAL isolated mock target with a synthetic SNI."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if force_tls12:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    raw = socket.create_connection((TARGET_IP, 443), timeout=5)
    with ctx.wrap_socket(raw, server_hostname=sni) as tls_sock:
        if body_bytes > 0:
            payload = b"A" * body_bytes
            req = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {sni}\r\n"
                f"User-Agent: Mozilla/5.0 Chrome/131.0.0.0\r\n"
                f"Content-Length: {len(payload)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode() + payload
        else:
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {sni}\r\n"
                f"User-Agent: Mozilla/5.0 Chrome/131.0.0.0\r\n"
                f"Connection: close\r\n\r\n"
            ).encode()
        tls_sock.sendall(req)
        while tls_sock.recv(4096):
            pass


def run_baseline() -> None:
    """Benign human & enterprise traffic — MUST produce 0 Suricata alerts, 0 Zeek notices, 0 artex-hunt FPs."""
    # Pauses yield mean ~3.5s (>3.0s) and stddev ~1.8s (>1.25s) while exercising benign lookalikes:
    # static asset 404s (/favicon.ico, /nonexistent-image.png), /.env.example, Cisco AnyConnect, and smartex-* UAs.
    benign_calls = [
        ("/dashboard", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0", 1.5),
        ("/assets/app.js", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0", 5.2),
        ("/favicon.ico", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0", 2.1),
        ("/+CSCOE+/logon.html", "Cisco AnyConnect/4.10", 6.1),
        ("/.env.example", "Mozilla/5.0 (X11; Linux x86_64) Firefox/132.0", 1.8),
        ("/login", "smartex-agent/1.0", 5.4),
        ("/login", "smartex-judge-prod", 2.3),
        ("/nonexistent-image.png", "Mozilla/5.0 Chrome/131.0.0.0", 0.0),
    ]
    for path, ua, pause in benign_calls:
        http_req(path, ua=ua)
        if pause > 0:
            time.sleep(pause)
    print("BASELINE_REPLAY_DONE")


def run_attack_behaviors() -> None:
    """Harmless behavioral replay exercising Suricata, Zeek, and `artex-hunt scan` detectors."""
    # 1. Explicit framework & Dragos UAs (Suricata sid:9100001, 9100014; Zeek Agentic_Harness_UserAgent)
    http_req("/login", ua="norma/0.4.1")
    http_req("/login", ua="artex-agent")
    http_req("/login", ua="artex-judge-r121")
    http_req("/login", ua="LLMLeak-RedTeam/1.0 (authorised-scan)")

    # 2. Canary probes, X-ARTX-KEY, JWT alg:none, LiteLLM MCP RCE probe (Suricata sid:9100009, 9100012, 9100015)
    http_req("/zzzrandom98765", ua="Mozilla/5.0 (security-testing; authorized)")
    http_req("/login?user=zz_no_such_user_1a2b&artex=1", method="POST", ua="Mozilla/5.0 (security-testing; authorized)")
    http_req(
        "/api/v1/status",
        headers={
            "X-ARTX-KEY": "lab-canary",
            "Authorization": "Bearer eyJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ.",
        },
    )
    http_req("/mcp-rest/test/tools/list", ua="python-httpx/0.28.1")

    # 3. Spec-driven OpenAPI targeting + 422 -> 200 -> GET readback + 4xx -> /.env 200 pivot
    http_req("/openapi.json", ua="python-httpx/0.28.1")
    http_req("/api/v1/update-documents", method="PUT", body=b"{}", ua="python-httpx/0.28.1")
    http_req("/api/v1/update-documents", method="PUT", body=b'{"ok":true}', ua="python-httpx/0.28.1")
    http_req("/api/v1/update-documents", method="GET", ua="python-httpx/0.28.1")
    http_req("/.env", ua="python-httpx/0.28.1")

    # 4. BLOODALCHEMY C2 URI + ARTEX console routes/headers/titles + port 8787 (sid:9100006, 9100010, 9100008, 9100003, 9100002)
    http_req("/Inform/logger/heartbeat", ua="artex-selfupdate")
    http_req("/api/exploration/graph", port=8787, ua="artex-enrich/1.0")
    http_req("/console", port=8787, ua="artex-enrich/1.0")

    # 5. Rapid edge VPN probing with Nuclei UA (6 hits -> triggers Suricata sid:9100005 detection_filter count 5)
    for uri in [
        "/+CSCOE+/winvista.html",
        "/+webvpn+/index.html",
        "/tmui/login.jsp",
        "/mgmt/tm/util/bash",
        "/+CSCOE+/winvista.html",
        "/+webvpn+/index.html",
    ]:
        http_req(uri, ua="Nuclei - Open-source project (v3.3)")
        time.sleep(0.1)

    # 6. Rapid HTTP 4xx burst across 22 distinct non-asset URIs (triggers Zeek Agentic_HTTP_Error_Burst)
    for i in range(22):
        http_req(f"/api/v1/enum-endpoint-{i:02d}", ua="python-httpx/0.28.1")
        time.sleep(0.05)

    # 7. Local isolated TLS SNI & TLS 1.2 cert issuer checks (Suricata sid:9100007, 9100004, 9100011, 9100013; Zeek C2/OAST/LLM)
    tls_req_with_sni("artex.lol", path="/sync", body_bytes=512, force_tls12=True)
    for sni in ("api.xcai.pro", "webhook.site", "abc123.oast.live", "api.anthropic.com"):
        tls_req_with_sni(sni, path="/sync", body_bytes=512)
        time.sleep(0.15)

    # 8. Sawtooth growing-context TLS 1.3 flow (6 sequential turns >=3.2s apart -> Zeek conn.log -> llm_sawtooth_context_flow)
    for size in (4000, 9500, 17500, 29000, 44000, 62000):
        tls_req_with_sni("relay-node-44.lab.local", path="/sync", body_bytes=size)
        time.sleep(3.2)

    print("ATTACK_BEHAVIOR_REPLAY_DONE")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "baseline"
    if mode == "baseline":
        run_baseline()
    elif mode == "attack":
        run_attack_behaviors()
    else:
        raise SystemExit(f"Unknown mode: {mode}")
