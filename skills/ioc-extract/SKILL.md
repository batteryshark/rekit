---
name: ioc-extract
description: "Pull indicators of compromise from a file or directory (URLs, IPs, domains, emails, md5/sha1/sha256 hashes, .onion, CVEs, BTC/ETH addresses, registry keys) — from text and from strings mined out of binaries. Every value is DEFANGED in output (hxxp://evil[.]com, 1[.]2[.]3[.]4) so a report can't ship a live IOC. Pure stdlib, read-only; never resolves or fetches anything."
---

# IOC Extractor

Pull **indicators of compromise** out of a file or directory — and defang them so the
output is safe to drop into a report. Pure-stdlib, read-only.

## When to use

Building a report, or triaging what a sample talks to: run it over source, configs, an
extracted archive, or a decompiled tree. It also mines strings out of binaries, so it
works on executables too.

## What it finds

URLs, IPv4, domains, emails, **file hashes** (md5/sha1/sha256), `.onion` addresses,
**CVEs**, crypto addresses (BTC/ETH), and Windows **registry keys**.

Everything is **defanged** in the output — `hxxps://evil[.]com/x`, `1[.]2[.]3[.]4`,
`user[@]bad[.]com` — so pasting the results can't create a live link or get a URL
auto-fetched. Both the raw `value` and the `defanged` form are in the JSON.

Noise control: domains are filtered against a filename-extension blocklist (so
`index.js` isn't a "domain"), IPs against octet + benign-address checks. It never
resolves, connects to, or validates any indicator.

## Usage

```bash
rekit run ioc-extract ./decompiled-src
rekit run ioc-extract ./sample.bin --format json
```

## Prerequisites

- **python3 ≥ 3.8** — pure stdlib, nothing to vendor.
