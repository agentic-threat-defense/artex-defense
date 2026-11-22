"""100% harmless mock OpenAPI / web portal target for air-gapped purple-team telemetry validation."""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PUT_SEEN: set[str] = set()


class MockTargetHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, code: int, body: bytes, content_type: str = "application/json", extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/openapi.json":
            self._send(200, json.dumps({"openapi": "3.0.0", "paths": {"/api/v1/update-documents": {}}}).encode())
        elif path in {"/dashboard", "/assets/app.js", "/assets/app.css", "/+CSCOE+/logon.html", "/.env.example", "/login"}:
            self._send(200, b"<html><title>Corp Portal</title><body>OK</body></html>", "text/html")
        elif path == "/api/v1/update-documents":
            self._send(200, b'{"status":"updated"}')
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
        _ = self._read_body()
        path = self.path.split("?", 1)[0]
        if path == "/sync":
            # Steady ~2KB response for sawtooth growing-context TLS flow validation
            self._send(200, b'{"ack":"' + (b"x" * 2048) + b'"}')
            return
        if path == "/login":
            self._send(401, b'{"error":"unauthorized"}')
            return
        self._send(404, b'{"error":"not_found"}')


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", 8080), MockTargetHandler)
    server.serve_forever()
