# Threat 3 — DNS hijacking / phishing: PoC post-mortem

*Source for the DNS section of the report. Numbers from the clean run
`evidence/dns-20261121-124101/`; re-runnable with
`threats/dns-hijack/run-dns.sh`.*

## What the threat is and why it is relevant

DNS hijacking redirects a trusted name to an attacker-controlled address. It
is a **fraud / social** attack: the victim is not forced, they are deceived
into giving up credentials to what looks like a site they trust. It matters
because it defeats user vigilance — the address bar shows the right name, and
if DNS agrees, there is little left for a careful user to notice. In a
large-scale system the same technique redirects service-to-service lookups,
not just human logins, so a poisoned resolver is a system-wide integrity
problem.

## How it is exploited

Three roles on the isolated lab network:

- **attacker** — a rogue `dnsmasq` that answers `bank-lab.example` with the
  address of a phishing clone, plus the clone site itself;
- **victim** — a host that resolves names and visits the result;
- **defender** — the protective resolver (the defence, below).

The attack, executed end to end:

1. The rogue resolver maps `bank-lab.example` → the clone's IP.
2. The victim, using that resolver, looks up the bank and is sent to the
   clone — a convincing "BankLab Online — Secure Sign In" page.
3. The victim submits credentials; the clone **captures them** to the
   attacker's drop file. The run captured
   `user='joao.silva' pass='Sup3rSecret!'` from the victim.

The whole attack hinges on controlling the resolver the victim uses — which
is why the defence and the residual risk both centre on the resolver.

## The defence: a protective, reputation-scoring resolver

Rather than trust every DNS answer, the protective resolver scores a domain
*before* answering, using the guide's formula:

    risk = category + reports + domain_age + dnssec + ip_reputation

and acts on the score: **resolve**, **warn**, or **sinkhole**. Measured
scores from the run:

| Domain | risk | decision |
|--------|-----:|----------|
| `bank-legit.example` (established, signed, clean) | −10 | ALLOW — resolves to the real IP |
| `secure-bank-login.example` (lookalike, lightly reported) | 55 | WARN — resolved but flagged |
| `bank-lab.example` (phishing: reported, new, unsigned, bad-IP) | 110 | SINKHOLE — answered `0.0.0.0`, never the clone |

With the victim pointed at the protective resolver, the same
`bank-lab.example` lookup returned `0.0.0.0` instead of the clone: the victim
could not reach the phishing site. The sinkhole is the response **in the data
path** — the attack is stopped at resolution time, before any page loads.

## Metrics, monitoring and SIEM response

The resolver logs every decision in a format the Wazuh `ssle-resolver`
decoder parses. The run produced **18 SINKHOLE, 2 WARN, 2 ALLOW** decisions,
and the SIEM turned them into alerts:

| Rule | Meaning | Fired |
|------|---------|------:|
| 100301 | suspicious domain (WARN) | 1 |
| 100302 | DNS hijack blocked (SINKHOLE) | 8 |
| 100303 | repeated hits = phishing campaign | 2 |

Two layers of response:

1. **Data-path sinkhole** — the resolver refuses to resolve the phishing
   name, for every lookup, immediately. This is the primary control.
2. **SIEM active response** — rule 100303 (a client repeatedly steered to
   phishing, i.e. likely a compromised host) triggers `firewall-drop`. In the
   run the repeatedly-phished client `10.255.255.58` was blocked on the
   resolver, cutting off a host that is generating a stream of phishing
   lookups.

## Post-mortem observations

- **Reputation is evidence about the past.** The defence works here because
  the phishing domain is reported, newly registered and unsigned. A *freshly
  registered* domain with no history and a clean IP would score low and slip
  through — ADTree counter-defence C1. Reputation raises the cost of
  phishing; it does not close it.
- **The defence only holds where the protective resolver is actually used.**
  The entire attack is "use a different resolver". If the attacker controls
  the victim's `resolv.conf` (e.g. after the C2 foothold of Threat 2), it can
  simply not consult the protective resolver. The structural fix is a *pinned*
  resolver configuration the host cannot be redirected away from — recorded as
  gap D3.5, and the clearest link between this threat and Threat 2.
- **DNSSEC would change the game but is not deployed.** Signed answers would
  let the resolver *prove* a forged record invalid rather than merely scoring
  it suspicious (gap D3.4). Here DNSSEC status is one input to the score, not
  an enforced check.
- **Offline-lab simplification.** Domain age, reports and IP reputation come
  from a static local table rather than live WHOIS/RDAP and threat feeds,
  because the lab has no internet during attacks. The scoring *logic* is real;
  only the data source is simulated, and this is stated plainly rather than
  hidden.
- **Containment held.** The rogue resolver and clone never left the lab: the
  lab bridge has no uplink and nftables blocks the home LAN, so a rogue
  DNS/DHCP service could not reach the real network — the specific danger the
  guide warns about.

## Reproduction and cleanup

```
bash threats/dns-hijack/run-dns.sh            # full cycle (~4 min)
bash threats/dns-hijack/run-dns.sh --cleanup  # remove the three containers
```

All attack infrastructure is in disposable containers; cleanup removes them
entirely. The telemetry architecture is untouched by this experiment — the
three DNS roles are separate containers on the same lab network.
