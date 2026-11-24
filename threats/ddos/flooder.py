#!/usr/bin/env python3
"""Bounded concurrent flooder for the DoS mitigation comparison.

Posts a fixed body (one sensor identity) `total` times across `workers`
threads and tallies response codes. One process using the standard library,
so it is fast and reliable where process-per-request (curl/ab) is not.

Usage: flooder.py <url> <total> <workers> <body_file>
Prints: "<201count> <429count> <other> <elapsed_s>"
"""
import sys
import threading
import time
import urllib.request

url, total, workers, body_file = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
body = open(body_file, "rb").read()

counts = {"201": 0, "429": 0, "other": 0}
lock = threading.Lock()
per = total // workers


def work():
    local = {"201": 0, "429": 0, "other": 0}
    for _ in range(per):
        req = urllib.request.Request(url, data=body,
                                     headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=3) as r:
                code = str(r.status)
        except urllib.error.HTTPError as e:
            code = str(e.code)
        except Exception:
            code = "other"
        local[code if code in local else "other"] += 1
    with lock:
        for k in counts:
            counts[k] += local[k]


t0 = time.time()
threads = [threading.Thread(target=work) for _ in range(workers)]
for t in threads:
    t.start()
for t in threads:
    t.join()
elapsed = time.time() - t0
print("%d %d %d %.1f" % (counts["201"], counts["429"], counts["other"], elapsed))
