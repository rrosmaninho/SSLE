# Threat 1 — Distributed Denial of Service: PoC post-mortem

*Source for the DDoS section of the report. Numbers are from the clean run
`evidence/ddos-20261121-072230/`; re-runnable with `threats/ddos/run-ddos.sh`.*

## What the threat is and why it is relevant

A denial-of-service attack degrades **availability** by exhausting a finite
resource — here the CPU of the ingestion service, the single entry point for
all sensor data. Availability is the property most directly exposed by a
service-oriented architecture: every sensor depends on ingestion, so making
ingestion unresponsive silences the whole telemetry pipeline without touching
any other component. The attack-surface probe confirmed the precondition:
`/ingest` is reachable and unauthenticated from anywhere on the lab network,
so any compromised neighbour can become a source.

## How it is exploited

Two ordinary lab containers (`load-client-a`, `load-client-b`) emulate a
small botnet, each sending a bounded HTTP POST workload to `/ingest` with
ApacheBench. This follows the DoS guide's methodology — a single-client
baseline compared against a simultaneous paired-client run, the same endpoint
and body throughout, and a resource-constrained target — and respects its
safety boundary: internal traffic only, a target capped at 10 % of one CPU,
a fixed time bound (20 s), and a snapshot taken first.

The one deviation from the guide's literal `ab -n 40` is volume. A C++
service answers 40 requests in a few milliseconds and shows nothing; the
experiment scales up enough to (a) saturate the throttled target and (b)
cross the Wazuh frequency thresholds, while staying bounded.

## Metrics and monitoring

| Scenario | Throughput | median | p95 | failed |
|----------|-----------:|-------:|----:|-------:|
| Baseline, unconstrained, 1 client | 1322 req/s | 1 ms | **1 ms** | 0 |
| Baseline, target throttled to 10 % CPU, 1 client | 1287 req/s | 1 ms | 1 ms | 0 |
| **Paired attack**, both clients, 10 % CPU | clients aborted | — | **78 ms (server p95)** | clients saturated |

Two independent signals detected the attack:

1. **Request rate (Wazuh).** The access-log frequency rules fired **101 times
   (rule 100101)** and **115 times (rule 100102)** — more than 120 and 300
   requests per 60 s from a single source. This is the fast signal: it does
   not depend on how the service performs, only on how many requests arrive.
2. **Latency and saturation (Prometheus).** Server-side p95 rose from **1 ms
   to 78 ms** (≈78×), computed from the `ssle_ingestion_latency_seconds`
   histogram. The target's cgroup recorded **70 CPU-throttle events totalling
   22.3 s throttled** during the 20 s attack — direct evidence it hit its CPU
   limit. The load clients could not complete their runs (ApacheBench aborted
   on socket timeout), which is the availability loss made visible from the
   client side.

**Why throughput alone is insufficient.** The baseline sustained 1322 req/s
with no ill effect; raw request volume does not by itself prove an attack — a
legitimate flash crowd looks the same. The evidence of a *denial* is the
combination: requests up **and** p95 up **and** CPU throttled **and** clients
failing to complete. This is why detection correlates the request-rate signal
with latency and saturation rather than alarming on volume alone.

## Response adopted

The defence has two layers, one proactive and one reactive.

**Proactive — per-identity rate limiting at the service.** The ingestion
service applies a token bucket *per sensor identity* (the hierarchical name in
the reading), defaulting to 5 req/s with a burst of 10. This is the control
the DoS guide names for the mitigation exercise, and it acts on the first
request, in the data path, before anything reaches storage. The before/after
comparison (`threats/ddos/mitigation-compare.sh`, evidence under
`evidence/ddos-mitigation-*/`) measures a bounded flood on one identity with
the control off and on:

| | served (201) | shed (429) | junk reaching storage |
|---|---:|---:|---:|
| without the control | all | 0 | ~3000 |
| with the control | ~burst | the rest | **~20** |

The control cut the attacker's impact on the data store from thousands of
rows to roughly the burst size — a ~150× reduction — because the flood is
rejected at the service. Crucially, keying the limit on **identity rather than
source IP** is what lets it coexist with scale: a node container hosting fifty
sensors presents one IP but fifty identities, so each legitimate sensor keeps
its own bucket and is never limited, while a flood that reuses one identity is
shed. (A direct check: ten real sensors ran with zero rate-limited requests
and ten active buckets, one per sensor.)

**Reactive — SIEM firewall-drop.** Wazuh's `firewall-drop` is wired to rule
**100102** (the *sustained* flood, level 12), not the first detection (100101,
level 10): blocking on the first threshold crossing would let a brief spike cut
a client off, so requiring the sustained pattern trades a little detection
delay for far fewer false positives. In the clean run it **blocked both
attacking source addresses** with an `iptables` DROP on the ingestion host,
within seconds, with Wazuh's default 600 s timeout.

The two layers are complementary: the rate limiter blunts the flood instantly
and protects the data, while the firewall-drop removes the source entirely
once the attack is confirmed sustained.

## Post-mortem observations

- **The cheap signal wins the race.** The request-rate rule fired and the
  block landed within seconds; the Prometheus `IngestionLatencyHigh` alert,
  with its deliberate 2-minute anti-flap window, never needed to fire because
  the attack was neutralised first. The layered detection behaved exactly as
  intended — the inexpensive request-count signal caught the attack before
  the slower latency-based alert would have.
- **A correct-by-design quirk surfaced.** On a repeated run the block did not
  re-apply: Wazuh keeps a list of currently-blocked keys and *aborts a
  duplicate block* within the active-response timeout. A manual `iptables`
  flush does not clear that list, so the experiment now restarts the target
  agent to reset the active-response state before each run. This is correct
  Wazuh behaviour (do not stack duplicate rules), not a fault.
- **Residual weakness — identity rotation.** Per-identity rate limiting raises
  the attacker's cost but does not close the attack: an attacker who cycles
  through many distinct sensor names gets one burst per name. That flood is no
  longer invisible, though — it appears as a surge of unknown and implausible
  sensor identities (caught by the anomaly rules, which flag readings from
  names and values that do not match any registered sensor) and as a growing
  rate-bucket count. The honest position is that the control shifts the attack
  from cheap-and-silent to costly-and-noisy, which is what a good control does.
  The ADTree records this as counter-defence C2.
- **The limiter protects data, not latency (measured, and the more important
  finding).** A capacity sweep — the same bounded flood against the target at a
  range of CPU allowances, with the limiter off vs on and a steady legitimate
  "prober" client measuring its own latency — showed that under a CPU-constrained
  target the per-identity limiter does **not** protect a legitimate user's
  latency, and at low capacity can make it *worse* (e.g. at 10 % CPU the prober's
  p95 was worse with the limiter on than off). The mechanism is in the code: a
  rate-limited request is received, JSON-parsed to extract its identity, and
  checked against its bucket **before** the 429 is returned
  (`modules/ingestion/src/main.cpp:122-141`) — cheaper than a stored request
  (it skips the storage forward) but not free. Because those rejections are fast,
  the closed-loop ApacheBench attackers send *more* per second, and at a tiny CPU
  budget the parse-and-bucket work still saturates the core, starving the
  legitimate user. So the limiter is a **data-integrity** control — it keeps junk
  out of storage: measured at **~40,000 rows undefended vs ~40–170 defended across
  1–32 attackers** (`docs/figures/ddos-attackers.png`), consistent with the
  ~3000→~20 single-identity result above — while **availability/latency is
  restored by the reactive firewall-drop**, which removes the source so no
  rejection cost remains (`docs/figures/ddos-firewall.png`). This refines the "two
  complementary layers" above: they protect *different properties* (integrity vs
  availability), not the same one twice. The effect is consistent with
  established practice — rejected requests still cost CPU, so rate limiting is
  most effective at the network/edge before traffic reaches the app, and
  closed-loop load generators self-throttle. (The effect **reproduced across two
  independent capacity-sweep runs**: the defended user p95 was ~5004/5004 ms at
  10 %, ~4102/4196 ms at 15 % and ~1098/2099 ms at 25 % — far worse than
  undefended — and better than undefended only at ≥50 %, placing the crossover at
  ~25–50 % capacity. The *undefended* numbers are noisy between runs, so quote the
  qualitative effect and ranges, not exact values; a third run would add rigour.)
- **Single point of failure, again.** Blocking protects ingestion, but the
  registry remains the architecture's weakest availability point: a single
  unauthenticated `POST /unregister` evicts a service with no flood at all
  (ADTree branch A1.2). Rate-limiting a flood does not address that.

## Reproduction and cleanup

```
bash threats/ddos/run-ddos.sh            # full cycle (~4 min)
bash threats/ddos/run-ddos.sh --cleanup  # remove clients, restore limits,
                                          # flush blocks, clean load-test rows
```

The target is snapshotted as `ingestion/pre-ddos` before the run, so recovery
is a revert rather than a rebuild. After cleanup the system was verified
healthy: ingestion active, no residual block, limits restored, data flowing
(storage row count increasing), and all `loadtest-*` rows removed.
