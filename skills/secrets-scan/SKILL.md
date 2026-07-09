---
name: secrets-scan
description: "Find leaked credentials in files: high-signal provider patterns (AWS/GitHub/Slack/Google/Stripe/OpenAI/SendGrid/Twilio/JWT/PEM private keys) plus a generic high-entropy secret-assignment catch with placeholder filtering. Matches are REDACTED in output — never echoes a full secret. Pure stdlib, read-only."
---

# Secrets Scanner

Find leaked credentials — API keys, tokens, private keys — in a file or a whole
tree. Pure-stdlib, read-only, and it **redacts** every match (never echoes a full
secret).

## When to use

Checking whether a package, dump, or repo you're analysing carries hard-coded
credentials — either an attacker's exfil target or a victim's leaked keys. Run it on
source, configs, `.env`, and extracted archives.

## What it finds

- **Provider patterns (high confidence):** AWS access keys, GitHub tokens/PATs, Slack
  tokens & webhooks, Google API keys, Stripe keys, OpenAI keys, npm/PyPI tokens,
  SendGrid, Twilio, JWTs, and PEM `PRIVATE KEY` blocks.
- **Generic (entropy-gated):** `api_key = "…"` / `password: "…"` style assignments
  whose value is high-entropy and not an obvious placeholder (`changeme`, `${VAR}`,
  `your_key_here`, …) → `SECRET.GENERIC_HIGH_ENTROPY`.

Every value is redacted to `prefix…suffix [N chars]`; private keys are reported as
presence only. It never validates a key against a live service — no network, ever.

## Usage

```bash
rekit run secrets-scan ./package
rekit run secrets-scan ./.env --format json
rekit run secrets-scan ./src --min-entropy 3.5   # stricter generic gate
```

## Prerequisites

- **python3 ≥ 3.8** — pure stdlib, nothing to vendor.

## Note

Regex/entropy heuristics find *candidates*, not proof — confirm before acting, and
remember a real find means the key should be rotated.
