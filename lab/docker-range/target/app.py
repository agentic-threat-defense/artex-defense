"""100% harmless mock OpenAPI / web portal / isolated UDP-53 DNS target for non-routed purple-team validation."""

from __future__ import annotations

import json
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PUT_SEEN: set[str] = set()
RAILS_GROOM_SIZES: set[int] = set()


def _build_dns_query(fqdn: str, txid: int = 0x4242) -> bytes:
    """Build a minimal RFC 1035 standard A-record DNS query packet."""
    qname = b"".join(bytes([len(lbl)]) + lbl.encode("ascii") for lbl in fqdn.strip(".").split(".") if lbl) + b"\x00"
    return struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


def _start_mock_dns_server(bind_ip: str = "0.0.0.0", port: int = 53) -> None:
    """Strictly isolated UDP/53 responder replying 127.0.0.1 for any A query (zero external forwarding)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((bind_ip, port))

    def _serve() -> None:
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                if len(data) < 12:
                    continue
                txid = data[:2]
                # Locate end of QNAME
                pos = 12
                while pos < len(data) and data[pos] != 0:
                    pos += 1 + data[pos]
                q_end = pos + 5
                if q_end > len(data):
                    continue
                question = data[12:q_end]
                hdr = txid + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
                # Pointer to QNAME at offset 12 (0xC00C), Type A (1), Class IN (1), TTL 60, RDLEN 4, 127.0.0.1
                answer = struct.pack("!HHHLH4s", 0xC00C, 1, 1, 60, 4, socket.inet_aton("127.0.0.1"))
                sock.sendto(hdr + question + answer, addr)
            except Exception:
                continue

    threading.Thread(target=_serve, daemon=True).start()


def _emit_isolated_oob_dns(fqdn: str, dns_server_ip: str = "172.30.0.10") -> None:
    """Emit a harmless isolated UDP/53 query inside the internal Docker bridge to test OOB DNS detection."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.5)
        sock.sendto(_build_dns_query(fqdn), (dns_server_ip, 53))
        try:
            sock.recvfrom(512)
        except OSError:
            pass
        sock.close()
    except OSError:
        pass


class MockTargetHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, code: int, body: bytes, content_type: str = "application/json", extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "keep-alive")
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/openapi.json":
            self._send(200, json.dumps({"openapi": "3.0.0", "paths": {"/api/v1/update-documents": {}}}).encode())
        elif path in {"/dashboard", "/assets/app.js", "/assets/app.css", "/+CSCOE+/logon.html", "/.env.example", "/login", "/function/workspace_docs"}:
            self._send(200, b"<html><title>Corp Portal</title><body>OK</body></html>", "text/html")
        elif path == "/cti-blog":
            self._send(
                200,
                b"<!DOCTYPE html><html><head><title>CTI Threat Report</title></head><body>Overview of Autonomous Penetration Testing Console frameworks.</body></html>",
                "text/html",
            )
        elif path == "/shop-redirect":
            self._send(
                200,
                b'<!DOCTYPE html><html><head><title>Artex</title><meta http-equiv="refresh" content="0;url=/shop/"/></head><body>Shop</body></html>',
                "text/html",
            )
        elif path == "/artex-redirect":
            self._send(
                200,
                b'<!DOCTYPE html><html><head><title>artex</title><meta http-equiv="refresh" content="0;url=/function/tasks/"/></head><body></body></html>',
                "text/html",
            )
        elif path == "/nearmiss-workbench":
            self._send(
                200,
                "<!DOCTYPE html><html><head><title>文献精读工作台 · Agent Workbench</title></head><body>OK</body></html>".encode("utf-8"),
                "text/html; charset=utf-8",
            )
        elif path == "/nearmiss-marketing":
            self._send(
                200,
                "<!DOCTYPE html><html><head><title>PentestCode — Security, Orchestrated.</title></head><body>OK</body></html>".encode("utf-8"),
                "text/html; charset=utf-8",
            )
        elif path == "/nearmiss-terminal":
            self._send(
                200,
                "<!DOCTYPE html><html><head><title>Xalgorix — Access Terminal</title></head><body>OK</body></html>".encode("utf-8"),
                "text/html; charset=utf-8",
            )
        elif path == "/api/health-benign":
            self._send(200, b'{"status":"ok","service":"smartex"}', "application/json")
        elif path == "/cti-health-blog":
            self._send(
                200,
                b'<!DOCTYPE html><html><head><title>CTI Advisory</title></head><body>ARTEX returns {"service":"artex"} on health checks.</body></html>',
                "text/html",
            )
        elif path == "/api/health":
            self._send(200, b'{"status":"ok","service":"artex"}', "application/json")
        elif path == "/console-luan1ao":
            self._send(
                200,
                "<!DOCTYPE html><html><head><title>鸾鸟渗透智能体 · Agent Workbench</title></head><body>Mock LuaN1aoAgent</body></html>".encode("utf-8"),
                "text/html; charset=utf-8",
            )
        elif path == "/console-pentestcode":
            self._send(
                200,
                b"<!DOCTYPE html><html><head><title>PentestCode</title></head><body>Mock PentestCode</body></html>",
                "text/html",
            )
        elif path == "/console-xalgorix":
            self._send(
                200,
                "<!DOCTYPE html><html><head><title>Xalgorix — Security Scanner</title></head><body>Mock Xalgorix</body></html>".encode("utf-8"),
                "text/html; charset=utf-8",
            )
        elif path in {"/api/v1/update-documents", "/api/v1/status", "/api/v1/profile"}:
            self._send(200, b'{"status":"ok"}')
        elif path == "/function/workspace":
            self._send(200, b'{"workspace":"artex_i18n_sim"}')
        elif path == "/console-kr":
            self._send(
                200,
                "<html><head><title>GOOGTEX — 자율 침투 테스트 콘솔</title></head><body>Mock KR console</body></html>".encode("utf-8"),
                "text/html; charset=utf-8",
            )
        elif path == "/console-en":
            self._send(
                200,
                b"<html><head><title>NKW - Autonomous Penetration Testing Console</title></head><body>Mock EN console</body></html>",
                "text/html",
            )
        elif path == "/api/v1/internal/credential-export":
            # Operator-planted honey route for deterministic canary_deception_tripwire validation
            self._send(200, b'{"export":"decoy_honey_route_only"}')
        elif path == "/api/v1/ssrf-sim":
            # Harmless isolated OOB DNS simulation inside internal:true Docker bridge
            _emit_isolated_oob_dns("a9f8e7d6c5b4a3928170.oob-exfil.example")
            self._send(200, b'{"simulated_oob_dns":true}')
        elif path == "/.env":
            self._send(200, b"APP_ENV=lab_synthetic_only\n")
        elif path == "/Inform/logger/heartbeat":
            self._send(200, b'{"ok":true}')
        elif path == "/api/exploration/graph":
            self._send(
                200,
                b"<html><title>ScopeWeaver</title><body>Mock console</body></html>",
                "text/html",
                extra_headers={"WWW-Authenticate": 'Basic realm="ARTEX"'},
            )
        elif path == "/console":
            self._send(
                200,
                "<html><title>自主渗透测试控制台</title><body>Mock console</body></html>".encode("utf-8"),
                "text/html; charset=utf-8",
            )
        elif path in {"/+CSCOE+/winvista.html", "/+webvpn+/index.html", "/tmui/login.jsp", "/mgmt/tm/util/bash"}:
            self._send(403, b'{"error":"forbidden"}')
        else:
            self._send(404, b'{"error":"not_found"}')

    def _read_body(self) -> bytes:
        try:
            length = max(0, int(self.headers.get("Content-Length", "0")))
        except ValueError:
            length = 0
        return self.rfile.read(length) if length > 0 else b""

    def do_PUT(self) -> None:
        _ = self._read_body()
        path = self.path.split("?", 1)[0]
        if path == "/api/v1/update-documents":
            if path not in PUT_SEEN:
                PUT_SEEN.add(path)
                self._send(422, b'{"error":"validation_error"}')
            else:
                self._send(200, b'{"status":"accepted"}')
            return
        self._send(404, b'{"error":"not_found"}')

    def do_POST(self) -> None:
        body = self._read_body()
        path = self.path.split("?", 1)[0]
        if path == "/api/v1/rails-form":
            # Benign European ISO-8859-1 text (single 0xDF, e.g. "Straße") -> 200 OK (0 FP baseline check).
            # Dense 0xDF heap-grooming sweep (b"\xdf" * 4+) simulates 3 Puma worker 502 crashes across distinct sizes then 200 recovery.
            if b"\xdf\xdf\xdf\xdf" in body or b"%df%df%df%df" in body.lower():
                RAILS_GROOM_SIZES.add(len(body))
                if len(RAILS_GROOM_SIZES) <= 3:
                    self._send(502, b'{"error":"bad_gateway_worker_restart"}')
                    return
                self._send(200, b'{"status":"processed"}')
                return
            self._send(200, b'{"status":"saved"}')
            return
        if path == "/sync":
            # Steady ~2KB response for multi-connection sawtooth growing-context TLS flow validation
            self._send(200, b'{"ack":"' + (b"x" * 2048) + b'"}')
            return
        if path == "/api/v1/llm-turn":
            # Simulate compact real-LLM server inference latency (~0.32s) & ~680B tool-call JSON response
            time.sleep(0.32)
            self._send(200, b'{"tool_call":"run_probe","args":"' + (b"p" * 640) + b'"}')
            return
        if path == "/login":
            self._send(401, b'{"error":"unauthorized"}')
            return
        self._send(404, b'{"error":"not_found"}')


if __name__ == "__main__":
    _start_mock_dns_server("0.0.0.0", 53)
    server = ThreadingHTTPServer(("127.0.0.1", 8080), MockTargetHandler)
    server.serve_forever()
