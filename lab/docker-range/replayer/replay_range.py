"""100% harmless behavioral traffic replayer for the non-routed isolated Docker Purple-Team Range.

Generates ONLY benign HTTP/TLS wire traffic against the local isolated mock target (172.30.0.20)
to exercise real Suricata 7, real Zeek LTS, and real Nginx -> `artex-hunt scan` pipelines.
Zero exploit payloads, zero offensive frameworks, zero external connections.
"""

from __future__ import annotations

import http.client
import socket
import ssl
import struct
import sys
import threading
import time
import urllib.error
import urllib.request

TARGET_IP = "172.30.0.20"


def _build_dns_query(fqdn: str, txid: int = 0x5151) -> bytes:
    qname = b"".join(bytes([len(lbl)]) + lbl.encode("ascii") for lbl in fqdn.strip(".").split(".") if lbl) + b"\x00"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def dns_query(fqdn: str, server_ip: str = TARGET_IP) -> None:
    """Send a harmless isolated UDP/53 DNS A-query inside the internal Docker bridge."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.5)
    try:
        sock.sendto(_build_dns_query(fqdn), (server_ip, 53))
        sock.recvfrom(512)
    except OSError:
        pass
    finally:
        sock.close()


def _start_local_dns_responder() -> socket.socket:
    """Isolated UDP/53 responder on replayer (172.30.0.10:53) so target OOB DNS gets a clean NOERROR reply."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", 53))

    def _serve() -> None:
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                if len(data) < 12:
                    continue
                pos = 12
                while pos < len(data) and data[pos] != 0:
                    pos += 1 + data[pos]
                q_end = pos + 5
                if q_end > len(data):
                    continue
                hdr = data[:2] + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
                ans = struct.pack("!HHHLH4s", 0xC00C, 1, 1, 60, 4, socket.inet_aton("127.0.0.1"))
                sock.sendto(hdr + data[12:q_end] + ans, addr)
            except OSError:
                break

    threading.Thread(target=_serve, daemon=True).start()
    return sock


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
    sni: str | None,
    path: str = "/sync",
    body_bytes: int = 0,
    *,
    force_tls12: bool = False,
    alpn: list[str] | None = None,
    ciphers: str | None = None,
) -> None:
    """Open a real TLS connection to the LOCAL isolated mock target with optional SNI/TLS version/ALPN/ciphers."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if force_tls12:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    if alpn:
        ctx.set_alpn_protocols(alpn)
    if ciphers:
        ctx.set_ciphers(ciphers)
    raw = socket.create_connection((TARGET_IP, 443), timeout=5)
    host_hdr = sni or TARGET_IP
    with ctx.wrap_socket(raw, server_hostname=sni) as tls_sock:
        if body_bytes > 0:
            payload = b"A" * body_bytes
            req = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host_hdr}\r\n"
                f"User-Agent: Mozilla/5.0 Chrome/131.0.0.0\r\n"
                f"Content-Length: {len(payload)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode() + payload
        else:
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host_hdr}\r\n"
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
        ("/nonexistent-image.png", "Mozilla/5.0 Chrome/131.0.0.0", 3.8),
    ]
    benign_browser_hdrs = {
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
    }
    for path, ua, pause in benign_calls:
        hdrs = benign_browser_hdrs if ("Chrome/" in ua or "Firefox/" in ua) else None
        http_req(path, ua=ua, headers=hdrs)
        if pause > 0:
            time.sleep(pause)
    # Benign European ISO-8859-1 form POST containing a single German 'ß' (0xDF) -> MUST produce 0 Suricata/artex-hunt FPs!
    http_req(
        "/api/v1/rails-form",
        method="POST",
        ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0",
        headers={**benign_browser_hdrs, "Content-Type": "application/x-www-form-urlencoded; charset=iso-8859-1"},
        body=b"street=Hauptstra\xdfe+12&city=Berlin",
    )
    time.sleep(4.2)
    # Single consistent benign TLS 1.3 stack + 2 normal benign DNS lookups -> MUST emit 1 wire JA4 and 0 FPs!
    dns_query("app.lab.local")
    time.sleep(2.4)
    tls_req_with_sni("app.lab.local", path="/dashboard")
    time.sleep(5.1)
    dns_query("status.corp.local")
    time.sleep(2.2)
    tls_req_with_sni("app.lab.local", path="/assets/app.js")
    print("BASELINE_REPLAY_DONE")


def _run_persistent_tls_causal_loop() -> None:
    """Single persistent Keep-Alive TLS 1.3 socket with 5 growing turns & interleaved HTTP probes."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    class _SNIConn(http.client.HTTPSConnection):
        def connect(self) -> None:
            raw = socket.create_connection((self.host, self.port), self.timeout)
            self.sock = self._context.wrap_socket(raw, server_hostname="relay-persist.lab.local")

    conn = _SNIConn(TARGET_IP, 443, context=ctx, timeout=15)
    interleaved_paths = ["/api/v1/status", "/api/v1/profile", "/api/v1/update-documents", "/openapi.json"]
    try:
        for idx, body_len in enumerate((1400, 2300, 3300, 4400, 5600)):
            payload = b'{"messages":"' + (b"M" * body_len) + b'"}'
            conn.request(
                "POST",
                "/api/v1/llm-turn",
                body=payload,
                headers={"Host": "relay-persist.lab.local", "Content-Type": "application/json", "Connection": "keep-alive"},
            )
            resp = conn.getresponse()
            resp.read()
            if idx < len(interleaved_paths):
                # Causally bracketed external tool action between consecutive TLS LLM turns!
                time.sleep(0.15)
                http_req(interleaved_paths[idx], ua="python-httpx/0.28.1")
                time.sleep(0.15)
    finally:
        conn.close()


def run_attack_behaviors() -> None:
    """Harmless behavioral replay exercising Suricata, Zeek, YARA, Wire JA4/JA4H, DNS OOB, & `artex-hunt scan`."""
    dns_srv = _start_local_dns_responder()
    try:
        _run_attack_behaviors_inner()
    finally:
        dns_srv.close()


def _run_attack_behaviors_inner() -> None:
    # 1. Explicit framework & Dragos UAs (Suricata sid:9100001, 9100014; Zeek Agentic_Harness_UserAgent)
    http_req("/login", ua="norma/0.4.1")
    http_req("/login", ua="artex-agent")
    http_req("/login", ua="artex-judge-r121")
    http_req("/login", ua="LLMLeak-RedTeam/1.0 (authorised-scan)")

    # 2. Canary probes (URI + POST body), SOAP OSExecute, X-ARTX-KEY, JWT alg:none, LiteLLM MCP RCE probe (Suricata sid:9100009, 9100016, 9100018, 9100012, 9100015)
    http_req("/zzzrandom98765", ua="Mozilla/5.0 (security-testing; authorized)")
    http_req("/login?user=zz_no_such_user_1a2b&artex=1", method="POST", ua="Mozilla/5.0 (security-testing; authorized)")
    http_req("/api/v1/comment", method="POST", body=b'{"comment":"ARTEX_WRITE_PROBE"}', ua="python-httpx/0.28.1")
    http_req(
        "/SAPControl",
        method="POST",
        body=b"<soapenv:Envelope><soapenv:Body><urn:OSExecute><command>id</command></urn:OSExecute></soapenv:Body></soapenv:Envelope>",
        headers={"Content-Type": "text/xml"},
        ua="python-httpx/0.28.1",
    )
    http_req(
        "/SAPControl",
        method="POST",
        body=b"<SOAP-ENV:Envelope><SOAP-ENV:Body><m:GetEnvironment/></SOAP-ENV:Body></SOAP-ENV:Envelope>",
        headers={"Content-Type": "text/xml"},
        ua="python-httpx/0.28.1",
    )
    http_req(
        "/uploads/.htaccess",
        method="POST",
        body=b"php_flag engine on\nSetHandler application/x-httpd-php\n",
        ua="python-httpx/0.28.1",
    )
    http_req(
        "/api/v1/status",
        headers={
            "X-ARTX-KEY": "lab-canary",
            "Authorization": "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJzdWIiOiJsYWIifQ.",
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

    # 7. Local isolated TLS SNI, TLS 1.2 cert issuer & REAL multi-stack FoxIO JA4 whiplash + raw-IP TLS (t13i...)
    #    Produces >=4 genuinely distinct real wire-computed JA4 hashes from 172.30.0.10:
    #    (a) TLS 1.2 default (`t12d...00`), (b) TLS 1.3 default (`t13d...00`),
    #    (c) TLS 1.3 + ALPN h2 (`t13d...h2`), (d) TLS 1.2 restricted ciphers (`t12d02...`),
    #    (e) Raw-IP TLS 1.3 with NO SNI (`t13i...00`).
    tls_req_with_sni("artex.lol", path="/sync", body_bytes=512, force_tls12=True)
    for sni in ("api.xcai.pro", "webhook.site", "abc123.oast.live", "169-254-169-254.sslip.io", "api.anthropic.com"):
        tls_req_with_sni(sni, path="/sync", body_bytes=512)
        time.sleep(0.15)
    tls_req_with_sni("relay-h2.lab.local", path="/sync", body_bytes=256, alpn=["http/1.1", "h2"])
    tls_req_with_sni("relay-h2-first.lab.local", path="/sync", body_bytes=256, alpn=["h2", "http/1.1"])
    tls_req_with_sni(
        "relay-tls12-min.lab.local",
        path="/sync",
        body_bytes=256,
        force_tls12=True,
        ciphers="ECDHE-RSA-AES128-GCM-SHA256:AES256-GCM-SHA384",
    )
    tls_req_with_sni(None, path="/sync", body_bytes=256)  # Raw-IP TLS (no SNI -> FoxIO JA4 `t13i...`)

    # 8. Sawtooth growing-context TLS 1.3 flow (6 sequential turns >=3.2s apart -> Zeek conn.log -> llm_sawtooth_context_flow)
    for size in (4000, 9500, 17500, 29000, 44000, 62000):
        tls_req_with_sni("relay-node-44.lab.local", path="/sync", body_bytes=size)
        time.sleep(3.2)

    # 9. Persistent single-socket Keep-Alive TLS 1.3 loop + causally interleaved HTTP probes
    #    (proves real OpenSSL NewSessionTicket stripping + encrypted_tls_agent_turn_loop + causal_tls_action_loop)
    _run_persistent_tls_causal_loop()

    # 10. Stripped-header HTTP browser-UA impersonation (real FoxIO JA4H ge11nn040000 claiming Chrome/131)
    http_req("/api/v1/status", ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0")
    http_req("/api/v1/profile", ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0")

    # 11. Deterministic deception honey-route hit (--canary-path /api/v1/internal/credential-export)
    http_req("/api/v1/internal/credential-export", ua="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0")

    # 12. Real isolated UDP/53 DNS OOB & IMDS wildcard-DNS lookups (Zeek dns.log + dns_oob_callback_after_probe)
    dns_query("xyz987.oast.live")
    dns_query("169-254-169-254.sslip.io")
    http_req("/api/v1/ssrf-sim", ua="python-httpx/0.28.1")

    # 13. Harmless Ruby2Shell (CVE-2026-132825) behavioral replay: ISO-8859-1 dense 0xDF heap-grooming sweep
    #     (3 distinct POST sizes triggering 502 worker crashes then 200 recovery -> Suricata sid:9100021 + web_memory_corruption_crash_loop)
    for pad_len in (32, 96, 192, 320):
        http_req(
            "/api/v1/rails-form",
            method="POST",
            ua="python-httpx/0.28.1",
            headers={"Content-Type": "application/x-www-form-urlencoded; charset=iso-8859-1"},
            body=b"_method=patch&q=" + (b"\xdf" * 16) + (b"A" * pad_len),
        )
        time.sleep(0.12)

    print("ATTACK_BEHAVIOR_REPLAY_DONE")


def run_proxy_collapse() -> None:
    """Single consistent TLS stack carrying 3 distinct UA families with 4xx errors (ja4_proxy_collapse_multi_ua)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Send 4 requests over identical TLS 1.3 stack (1 wire JA4) with 3 distinct UA families (Chrome, curl, python)
    for path, ua in [
        ("/api/v1/missing-1", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0.0.0"),
        ("/api/v1/missing-2", "curl/8.5.0"),
        ("/api/v1/missing-3", "python-httpx/0.28.1"),
        ("/api/v1/missing-4", "curl/8.5.0"),
    ]:
        # Also send identical plaintext HTTP UAs so Zeek/Nginx logs the UA families alongside the single TLS JA4
        tls_req_with_sni("proxy-collapse.lab.local", path=path)
        http_req(path, ua=ua)
        time.sleep(0.1)
    print("PROXY_COLLAPSE_REPLAY_DONE")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "baseline"
    if mode == "baseline":
        run_baseline()
    elif mode == "attack":
        run_attack_behaviors()
    elif mode == "proxy_collapse":
        run_proxy_collapse()
    else:
        raise SystemExit(f"Unknown mode: {mode}")
