#!/usr/bin/env python3
"""devbox-ai-proxy — zero-dependency host-side AI proxy.

Keeps real credentials on the *host* so disposable devboxes never hold them.
For each route it injects auth from one of:

  * a static API key         -> "env:OPENAI_API_KEY"
  * a token read *fresh* from a file on every request (OAuth access tokens that
    the host keeps refreshed) -> "token-file:~/.claude/.credentials.json#claudeAiOauth.accessToken"
  * the output of a command  -> "token-cmd:some-command"

Responses are streamed (SSE-friendly). Python standard library only — no pip.

Config: JSON at $DEVBOX_PROXY_CONFIG (defaults to proxy.config.example.json next
to this file). See that file for the shape.
"""
import http.client
import json
import os
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

CONFIG_PATH = os.environ.get(
    "DEVBOX_PROXY_CONFIG",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "proxy.config.example.json"),
)
with open(CONFIG_PATH) as _f:
    CONFIG = json.load(_f)

LISTEN = CONFIG.get("listen", "0.0.0.0:4000")
_HOST, _PORT = LISTEN.rsplit(":", 1)
BIND_HOST = "" if _HOST in ("0.0.0.0", "*") else _HOST
BIND_PORT = int(_PORT)
ROUTES = CONFIG.get("routes", [])

# hop-by-hop + length/host headers we never forward verbatim
DROP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length", "host",
}


def resolve_source(source: str) -> str:
    if source.startswith("env:"):
        return os.environ.get(source[4:], "")
    if source.startswith("token-file:"):
        path, _, dotted = source[len("token-file:"):].partition("#")
        try:
            with open(os.path.expanduser(path)) as fh:
                data = json.load(fh)
        except Exception:
            return ""
        if dotted:
            for key in dotted.split("."):
                if isinstance(data, dict):
                    data = data.get(key, "")
                else:
                    return ""
        return data if isinstance(data, str) else ""
    if source.startswith("token-cmd:"):
        try:
            return subprocess.check_output(
                source[len("token-cmd:"):], shell=True, text=True
            ).strip()
        except Exception:
            return ""
    return ""


def match_route(path: str):
    for route in ROUTES:
        if path.startswith(route.get("match", "")):
            return route
    return None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "devbox-ai-proxy"

    def log_message(self, fmt, *args):  # to stderr, quiet-ish
        sys.stderr.write("[devbox-ai-proxy] %s %s\n" % (self.command, self.path))

    def _proxy(self):
        route = match_route(self.path)
        if route is None:
            self.send_error(404, "no matching route")
            return
        up = urlsplit(route["upstream"])

        length = int(self.headers.get("Content-Length", 0) or 0)
        body = self.rfile.read(length) if length else None

        strip = {h.lower() for h in (route.get("strip_headers") or [])}
        headers = {
            k: v for k, v in self.headers.items()
            if k.lower() not in DROP and k.lower() not in strip
        }
        auth = route.get("auth")
        if auth:
            hname = auth["header"]
            headers = {k: v for k, v in headers.items() if k.lower() != hname.lower()}
            headers[hname] = auth.get("prefix", "") + resolve_source(auth["source"])
        for k, v in (route.get("set_headers") or {}).items():
            headers[k] = v
        headers["Host"] = up.netloc

        conn_cls = http.client.HTTPSConnection if up.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(up.hostname, up.port or (443 if up.scheme == "https" else 80), timeout=600)
        try:
            conn.request(self.command, self.path, body=body, headers=headers)
            resp = conn.getresponse()
        except Exception as exc:  # upstream unreachable / TLS / etc.
            self.send_error(502, "upstream error: %s" % exc)
            return

        # Stream back with Connection: close (no re-chunking; works for SSE).
        self.send_response(resp.status, resp.reason)
        for k, v in resp.getheaders():
            if k.lower() in DROP:
                continue
            self.send_header(k, v)
        self.send_header("Connection", "close")
        self.end_headers()
        try:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            conn.close()
        self.close_connection = True

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_OPTIONS = _proxy


def main():
    srv = ThreadingHTTPServer((BIND_HOST, BIND_PORT), Handler)
    sys.stderr.write(
        "[devbox-ai-proxy] listening on %s:%d  (config: %s, %d route(s))\n"
        % (_HOST, BIND_PORT, CONFIG_PATH, len(ROUTES))
    )
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        sys.stderr.write("\n[devbox-ai-proxy] shutting down\n")


if __name__ == "__main__":
    main()
