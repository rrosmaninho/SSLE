#!/usr/bin/env python3
"""
Protective DNS resolver - the defence for Threat 3 (DNS hijacking / phishing).

Instead of trusting every DNS answer, this resolver scores a domain before
answering. The score follows the guide's formula:

    risk = category + reports + domain_age + dnssec + ip_reputation

and the decision follows the score:

    risk >= sinkhole threshold  -> SINKHOLE (answer 0.0.0.0, do not resolve)
    risk >= warn threshold      -> WARN (resolve, but flag it)
    otherwise                   -> ALLOW (resolve normally)

Every decision is logged in a format the Wazuh ssle-resolver decoder parses:

    <ISO8601> ssle-resolver action=SINKHOLE domain=bank-lab.example risk=110 client=10.255.255.40 reason=phishing,young-domain,unsigned

so the SIEM raises 100301 (WARN) / 100302 (SINKHOLE) / 100303 (campaign).

Reputation data is served from a local JSON table (reputation.json) because
the lab is offline during attacks; the real sources (WHOIS/RDAP, threat-intel
feeds, live DNSSEC validation) are named in that file and discussed in the
report as a limitation.

Usage: protective-resolver.py [reputation.json] [listen_ip] [log_path]
Requires python3-dnslib.
"""
import datetime
import json
import os
import socket
import socketserver
import sys

from dnslib import RR, QTYPE, A, DNSRecord, RCODE

REPUTATION = sys.argv[1] if len(sys.argv) > 1 else "/opt/ssle-dns/reputation.json"
LISTEN_IP = sys.argv[2] if len(sys.argv) > 2 else "0.0.0.0"
LOG_PATH = sys.argv[3] if len(sys.argv) > 3 else "/var/log/ssle/dns-resolver.log"
SINKHOLE_IP = "0.0.0.0"
TTL = 60

FACTORS = ("category", "reports", "domain_age", "dnssec", "ip_reputation")


def load_reputation():
    with open(REPUTATION) as f:
        data = json.load(f)
    return data["thresholds"], data["default"], data["domains"]


def score(entry):
    return sum(int(entry.get(f, 0)) for f in FACTORS)


def reasons(entry):
    """Human-readable reasons for the log, from whichever factors are high."""
    r = []
    if entry.get("category", 0) >= 20:
        r.append("bad-category")
    if entry.get("reports", 0) >= 5:
        r.append("reported")
    if entry.get("domain_age", 0) >= 15:
        r.append("young-domain")
    if entry.get("dnssec", 0) > 0:
        r.append("unsigned")
    if entry.get("ip_reputation", 0) >= 10:
        r.append("bad-ip-reputation")
    return ",".join(r) if r else "clean"


def log_decision(action, domain, risk, client, reason):
    line = "%s ssle-resolver action=%s domain=%s risk=%d client=%s reason=%s" % (
        datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        action, domain, risk, client, reason)
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")
    except Exception as e:
        print("log error:", e, file=sys.stderr)
    print(line, flush=True)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        client = self.client_address[0]
        try:
            request = DNSRecord.parse(data)
        except Exception:
            return
        qname = str(request.q.qname).rstrip(".")
        qtype = QTYPE[request.q.qtype]
        reply = request.reply()

        thresholds, default, domains = self.server.reputation
        entry = domains.get(qname, default)
        risk = score(entry)
        reason = reasons(entry)

        if risk >= thresholds["sinkhole"]:
            action = "SINKHOLE"
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(SINKHOLE_IP), ttl=TTL))
        elif risk >= thresholds["warn"]:
            action = "WARN"
            self._answer(reply, request, entry)
        else:
            action = "ALLOW"
            self._answer(reply, request, entry)

        log_decision(action, qname, risk, client, reason)
        sock.sendto(reply.pack(), self.client_address)

    def _answer(self, reply, request, entry):
        """Resolve from the local table. Offline lab: a real resolver would
        forward to an upstream here; the table stands in for that."""
        ans = entry.get("answer")
        if ans:
            reply.add_answer(RR(request.q.qname, QTYPE.A, rdata=A(ans), ttl=TTL))
        else:
            reply.header.rcode = RCODE.NXDOMAIN


class Server(socketserver.ThreadingUDPServer):
    allow_reuse_address = True

    def __init__(self, addr):
        super().__init__(addr, Handler)
        self.reputation = load_reputation()


if __name__ == "__main__":
    srv = Server((LISTEN_IP, 53))
    print("protective resolver listening on %s:53 (reputation=%s)" % (LISTEN_IP, REPUTATION),
          flush=True)
    srv.serve_forever()
