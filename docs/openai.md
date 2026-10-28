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
  redactor below does not see it, and from Community 1.0.0 it is recorded in `scan_response_ai_system_prompt.txt`, beside
  the payload (Community 0.2.57 and earlier recorded no system prompt). The Enterprise plugin pack scrubs
  the block with its own pass before adding it, whatever `OPENAI_REDACT` says: the target host on each finding becomes
  `[target-N]`; e-mail addresses, private and loopback IPv4 addresses (unless `REDACT_INTERNAL_IPS=false`), URLs to
  private addresses, colon-form MAC addresses, SNMP community strings and `.internal` / `.local` / `.corp` / `.lan` /
  `.intra` / `.priv` hostnames are masked; `NSA_AI_REDACT_LEVEL=strict` adds config and key file paths, AWS key IDs and
  Bearer tokens. Public addresses and hostnames elsewhere in the block are not masked. Measured on 2026-10-11, the block
  for a router scan carried no address, hostname, e-mail address or account ID, and a cloud scan's block was empty.

With `OPENAI_REDACT=true` (the default), before the payload is sent:

- the top-level host is replaced with `[REDACTED_HOST]`, and a private IPv4 address left in the summary also becomes
  `[REDACTED_HOST]` (a public one is `[IP]` there, as everywhere);
- public IPv4 addresses anywhere in the payload are replaced with `[IP]`;
- private-range IPv4 addresses (10/8, 172.16/12, 192.168/16) in service and evidence strings are replaced with `[REDACTED_IP]`;
- colon-separated MAC addresses become `[MAC]`, full-form IPv6 addresses `[IPv6]`, and link-local IPv6 `[FE80::/64]`;
- serial numbers — a `Serial: …` string or a `serial` / `serialNumber` / `sn` field — become `[REDACTED_HIDDEN]`, always;
- a scanned service's Set-Cookie value (its session token) is redacted;
- the fields `ip6`, `deviceWebPage`, `deviceWebPageInstruction`, `hardwareVersion` and `firmwareVersion` are dropped;
- any field whose key matches `CONFIDENTIAL_KEYWORDS` (for example `serial,password,token,secret`) is replaced with `[REDACTED_HIDDEN]`.
- from Community 1.0.0, an AWS account ID found in an ARN's account field (any partition) or in the account segment of an
  `amazonaws.com/<id>/…` URL becomes `[ACCOUNT_ID]` — there and everywhere else it occurs, inside resource names too (the
  names themselves are kept) — and any other 12-digit number becomes `[REDACTED_ID]`, a neutral label, since a 12-digit
  number in a banner is not necessarily an account. Community 0.2.57 and earlier send both.

**Not masked** (measured on 2026-10-11 against a router and an AWS account, with a real request): cloud resource names
themselves — bucket, queue, topic and user names stay, with any account ID inside them masked from Community 1.0.0; a
12-digit ID glued to letters (`logs123456789012`) that no ARN or AWS URL in the payload names; Azure subscription IDs and
GCP project IDs and numbers (not measured — a GCP project number is 12 digits and falls under the `[REDACTED_ID]` rule, a
GCP project ID is free text and cannot be masked by shape); AWS access-key IDs (`AKIA…`, `ASIA…` — on the measured run they were not sent, but only because they
sit in the scan's findings rather than in the evidence the payload carries); hostnames, e-mail addresses and certificate
subjects in service banners and certificate details; compressed IPv6 addresses; dash- and dot-form MAC addresses. **Inspect the payload file below before using the AI stage on
production data**, extend `CONFIDENTIAL_KEYWORDS` for fields you do not want to leave the host, and use a local Ollama
model where none of this may leave it.

## What is written, and where

Every scan writes into its own per-scan folder under `--out`. The AI stage adds:

| File | Contents |
|---|---|
| `scan_response_ai_payload.json` | The scan payload sent to OpenAI, written **before** the request — your audit record of the scan data that left the machine. The system prompt is the next row |
| `scan_response_ai_system_prompt.txt` | From Community 1.0.0: the system prompt sent with it — the prompt mode's own text, preceded on Pro and Enterprise by the intelligence block — written **before** the request. With the payload file it is the content of the request; the model name and your key are the rest |
| `scan_response_ai.json` | The raw API response. From Community 1.1.1 it also carries `nsauditorMeta.inputCoverage` when the provider reported an input count (see the next section) |
| `scan_response_ai.txt` / `.html` | The model's assessment as text and HTML |
| `scan_response_ai_error.json` | Written if the call fails or times out; `scan_response_ai.txt` then holds a readable failure notice naming the error |

## When the provider reads part of the input

From Community 1.1.1, after every response the AI stage compares the input tokens the provider reports with an estimate
of the input's size: the characters of the system prompt and the payload, divided by four. When the provider reports
reading less than half of that estimate:

- `scan_response_ai.json` records `nsauditorMeta.inputCoverage` with `inputTruncated: true`, `providerInputTokens` and
  `estimatedInputTokens`;
- `scan_response_ai.txt` and `scan_response_ai.html` open with one line: *the provider reports reading N tokens of an
  input estimated at M; this assessment covers part of the scan*;
- the console summary line and the run record carry the same figures for that host.

What was measured, on 2026-10-28: the four OpenAI runs (three network scans and an AWS scan) reported 1.12 to 1.26
times the estimate. A scan sent
through Ollama 0.40.11 and `llama3.2`, with Ollama's settings left at their defaults, reported reading 2,050 tokens of
an input estimated at 19,992 (about 80,000 characters), so the model assessed about a tenth of the scan, and before this
release nothing said so. If the line appears with Ollama, check the model's context length in your Ollama
configuration and re-run until the line is gone. A provider that reports no input count is recorded as unknown, never
as whole. The Claude provider's `input_tokens` is read the same way; the threshold was not measured on it.

## Timeouts

The request timeout scales with payload size: 120 s minimum, plus 15 s per KB, capped at 10 minutes, so large cloud-scan payloads get more time than small host scans. Override with `NSA_AI_TIMEOUT_MS`. A failed or timed-out call writes `scan_response_ai_error.json` plus a `scan_response_ai.txt` that names the error (and `NSA_AI_TIMEOUT_MS` when it was a timeout), so a missing assessment is never silent.

## Compliance notes

- The AI assessment is advisory narrative. Compliance evidence packs and control determinations come from the scan and the compliance engine, not from the model.
- Record the provider, model and prompt mode used for any report you hand to an auditor, and keep `scan_response_ai_payload.json` and `scan_response_ai_system_prompt.txt` with it.
- Your OpenAI organization's own data-retention and data-use settings apply to the request; NSAuditor AI does not change them.

See [configuration.md](./configuration.md) for every AI-related variable.
