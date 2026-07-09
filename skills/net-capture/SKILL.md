---
name: net-capture
description: "DYNAMIC: capture a target's network traffic to a pcap while it runs (tcpdump), then summarize packets, talking-to IPs, and DNS queries. Point --iface at a sinkholed interface for safer detonation. EXECUTES the target and captures on an interface (usually needs root); consent-gated."
---

# Network Capture

**⚡ Dynamic tier — runs the target and sniffs the wire.** Run only where you don't
mind the risk (ideally an isolated/sinkholed network).

## When to use

You want to see what a sample *talks to* — C2, exfil, downloads. `net-capture` runs it
while capturing the interface, then shows the IPs it reached and DNS it asked for, and
leaves a pcap for deeper analysis.

## What it does

Starts `tcpdump` on an interface, runs the target for a bounded duration, stops the
capture, and summarizes: packet count, talkers (IPs), and DNS query lines. Writes the
full `capture.pcap`. For safe detonation, run inside a VM with a **sinkholed/proxied**
network and point `--iface` at it.

## Consent & prerequisites

- Dynamic: `rekit run --allow-dynamic net-capture <target>` (or `--yes-i-consent` /
  `REKIT_ALLOW_DYNAMIC=1`).
- **`tcpdump`** on PATH; **capturing usually needs root** (sudo / capture caps). Absent
  or unprivileged → the runner reports the honest failure.

## Usage

```bash
rekit run --allow-dynamic net-capture ./sample --iface eth0 --duration 20
```

Feed the recovered IPs/domains into `ioc-extract`.
