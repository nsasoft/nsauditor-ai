# Using NSAuditor AI with OpenAI

NSAuditor AI can send a redacted summary of each scan to an OpenAI model and save the model's written assessment and remediation guidance next to the scan output. This page covers setup, exactly what is sent, and where everything is written.

The AI stage is **opt-in** and runs on **your own OpenAI API key**. Data goes straight from your machine to OpenAI under your account; Nsasoft never receives scan data, prompts or responses. OpenAI is one of three supported providers (`openai`, `claude`, `ollama`) and is the default when `AI_PROVIDER` is not set. For air-gapped or no-egress deployments, use a local Ollama model instead — OpenAI mode needs outbound HTTPS to the OpenAI API.

## Setup

Add to `.env` (or export in the shell):

```ini
AI_ENABLED=true                 # the AI stage is off unless this is true
AI_PROVIDER=openai
OPENAI_API_KEY=sk-...           # or a keychain:<label> reference
OPENAI_MODEL=gpt-6-luna         # built-in default from Community 1.0.0 (gpt-4o-mini before); set any model your account can use
OPENAI_PROMPT_MODE=optimized    # basic (default) | pro | optimized
OPENAI_REDACT=true              # default true — leave on
```

Then run a scan as usual, for example (a private range needs `NSA_ALLOW_ALL_HOSTS=1` on the CLI — without it the scan is
refused before anything runs):

```bash
NSA_ALLOW_ALL_HOSTS=1 nsauditor-ai scan --host 10.0.0.0/24 --plugins all \
  --compliance soc2 --output-format md --out ./evidence/
```

If the stage is skipped, the log says why: `AI_ENABLED is not set to true`, or `AI_ENABLED=true but the API key could not be resolved` (the key variable is empty or its `keychain:` reference did not resolve).

## What is sent to OpenAI

One request per scan: a system prompt (selected by `OPENAI_PROMPT_MODE`) and the scan payload.

- **CE** sends the basic scan summary — services, ports, versions.
- **Pro and Enterprise** add an intelligence block — CVE matches, KEV and EPSS where a store was applied, MITRE ATT&CK
  technique annotations and composite risk scores — for better-grounded output. **It travels in the SYSTEM PROMPT**: the
  redactor below does not see it, and `scan_response_ai_payload.json` does not record it. Measured on 2026-10-11, the block
  for a router scan carried no address, hostname, e-mail address or account ID, and a cloud scan's block was empty.

With `OPENAI_REDACT=true` (the default), before the payload is sent:

- the top-level host is replaced with `[REDACTED_HOST]`, and every IPv4 address in the summary with `[REDACTED_HOST]`;
- public IPv4 addresses anywhere in the payload are replaced with `[IP]`;
- private-range IPv4 addresses (10/8, 172.16/12, 192.168/16) in service and evidence strings are replaced with `[REDACTED_IP]`;
- colon-separated MAC addresses become `[MAC]`, full-form IPv6 addresses `[IPv6]`, and link-local IPv6 `[FE80::/64]`;
- serial numbers — a `Serial: …` string or a `serial` / `serialNumber` / `sn` field — become `[REDACTED_HIDDEN]`, always;
- a scanned service's Set-Cookie value (its session token) is redacted;
- the fields `ip6`, `deviceWebPage`, `deviceWebPageInstruction`, `hardwareVersion` and `firmwareVersion` are dropped;
- any field whose key matches `CONFIDENTIAL_KEYWORDS` (for example `serial,password,token,secret`) is replaced with `[REDACTED_HIDDEN]`.

**Not masked** (measured on 2026-10-11 against a router and an AWS account, with a real request): **AWS account IDs and
ARNs** — bare, inside resource names such as bucket names, in SQS queue URLs and in SNS topic ARNs — and cloud resource
names themselves; AWS access-key IDs (`AKIA…`, `ASIA…` — on the measured run they were not sent, but only because they
sit in the scan's findings rather than in the evidence the payload carries); hostnames, e-mail addresses and certificate
subjects in service banners and certificate details; compressed IPv6 addresses; dash- and dot-form MAC addresses. **Inspect the payload file below before using the AI stage on
production data**, extend `CONFIDENTIAL_KEYWORDS` for fields you do not want to leave the host, and use a local Ollama
model where none of this may leave it.

## What is written, and where

Every scan writes into its own per-scan folder under `--out`. The AI stage adds:

| File | Contents |
|---|---|
| `scan_response_ai_payload.json` | The scan payload sent to OpenAI, written **before** the request — your audit record of the scan data that left the machine. It does not include the system prompt, which on Pro and Enterprise carries the intelligence block |
| `scan_response_ai.json` | The raw API response |
| `scan_response_ai.txt` / `.html` | The model's assessment as text and HTML |
| `scan_response_ai_error.json` | Written if the call fails or times out; `scan_response_ai.txt` then holds a readable failure notice naming the error |

## Timeouts

The request timeout scales with payload size: 120 s minimum, plus 15 s per KB, capped at 10 minutes, so large cloud-scan payloads get more time than small host scans. Override with `NSA_AI_TIMEOUT_MS`. A failed or timed-out call writes `scan_response_ai_error.json` plus a `scan_response_ai.txt` that names the error (and `NSA_AI_TIMEOUT_MS` when it was a timeout), so a missing assessment is never silent.

## Compliance notes

- The AI assessment is advisory narrative. Compliance evidence packs and control determinations come from the scan and the compliance engine, not from the model.
- Record the provider, model and prompt mode used for any report you hand to an auditor, and keep `scan_response_ai_payload.json` with it.
- Your OpenAI organization's own data-retention and data-use settings apply to the request; NSAuditor AI does not change them.

See [configuration.md](./configuration.md) for every AI-related variable.
