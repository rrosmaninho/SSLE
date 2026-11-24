#!/usr/bin/env python3
"""Steady legitimate client for the DDoS time-series.

Posts a fixed body at a constant rate with its OWN sensor identity (so the
per-identity rate limiter treats it as a legitimate user, not part of the
flood), and logs 'epoch_seconds latency_ms' per request. The capture harness
reads this log to plot the latency a real user experiences through the attack.

  prober.py <url> <body_file> <rate_hz> <logfile>
"""
import sys, time, urllib.request

url, body_file, rate, logf = sys.argv[1], sys.argv[2], float(sys.argv[3]), sys.argv[4]
body = open(body_file, "rb").read()
interval = 1.0 / rate
with open(logf, "a", buffering=1) as f:
    while True:
        t0 = time.time()
        try:
            req = urllib.request.Request(url, data=body,
                                         headers={"Content-Type": "application/json"})
            urllib.request.urlopen(req, timeout=5).read()
        except Exception:
            pass
        f.write("%.3f %.2f\n" % (t0, (time.time() - t0) * 1000.0))
        s = interval - (time.time() - t0)
        if s > 0:
            time.sleep(s)
