# Configuration Reference

Every environment variable NSAuditor AI reads, with its default and its effect. Split out of the top-level [README](../README.md) because npm truncates a rendered README at roughly 64 KiB.

### Environment Variables (.env)

**AI configuration:**

```ini
AI_ENABLED=false                     # Set to true to enable AI analysis
AI_PROVIDER=openai                   # openai | claude | ollama
OPENAI_API_KEY=sk-...               # Your OpenAI key
OPENAI_MODEL=gpt-4o-mini
ANTHROPIC_API_KEY=sk-ant-...        # Your Claude key
ANTHROPIC_MODEL=claude-sonnet-4-6
OPENAI_PROMPT_MODE=optimized        # basic | pro | optimized
OPENAI_REDACT=true                  # Redact before sending to AI
CONFIDENTIAL_KEYWORDS=serial,password,token,secret
```

**Plugin-specific:**

```ini
TLS_SCANNER_TIMEOUT_MS=8000
TLS_SCANNER_VERSIONS=TLSv1,TLSv1.1,TLSv1.2,TLSv1.3
TLS_SCANNER_PORTS=443:https,465:smtps,563:nntps,993:imaps,995:pop3s
OPENSEARCH_SCANNER_TIMEOUT_MS=6000
OPENSEARCH_SCANNER_INSECURE_TLS=false
DNS_TIMEOUT_MS=800
HTTP_PROBE_TIMEOUT_MS=6000
WEBAPP_DETECTOR_TIMEOUT_MS=6000
SMB_NULL_SESSION=false
SMB_NULL_SESSION_TIMEOUT=5000
ENABLE_SYN_SCAN=false
SYN_SCAN_PORTS=
SYN_SCAN_TIMEOUT=30000
PING_FALLBACK=true
PING_FALLBACK_TIMEOUT=2000
```

**Licensing (Pro/Enterprise):**

```ini
NSAUDITOR_LICENSE_KEY=pro_eyJhbGci...   # Pro or Enterprise license key
NSAUDITOR_PLUGIN_PATH=                   # Additional plugin directories (colon-separated)
```

**Longitudinal compliance evidence (Enterprise CLI, new alongside the variables below):**

A single scan shows configuration at an instant. A SOC 2 Type II auditor — and the ISO
surveillance cadence, PCI DSS v4.0.1 Section 6 sampling (the assessor's documented determination; the standard prescribes no size), HIPAA §164.312(b) and GDPR Art. 32(1)(d)
equivalents — asks whether controls operated over a *period*. Every scan has always written
a per-framework `scan_attestation_<framework>.json`, so a history you already have is
aggregatable today:

```bash
# Track remediation SLA / MTTR against a directory of prior scans
nsauditor-ai scan --host aws --compliance soc2 \
  --compliance-history ./out --sla-policy ./my-sla.json

# Roll a directory of prior scans up into a multi-period attestation
nsauditor-ai compliance attest --history ./out --framework soc2 --window 12m
```

Three things the roll-up states about itself rather than leaving you to discover:
discovery reads **one** directory level (`<history-root>/<scan-id>/`), scans whose own
attestation is marked `REPORT INVALID FOR AUDIT` are **counted and named** rather than
averaged into a clean verdict, and an empty history exits **3** with status `no_evidence` —
absence of evidence is a finding, not a pass.

**The approval commands (CE 0.2.40 / Enterprise 0.35.0).** Four more `compliance` subcommands, all
forwarding to Enterprise — they need `@nsasoft/nsauditor-ai-ee` installed and exit 2 with an
explanatory message if it is absent. CLI-only; the MCP surface does not reach them.

```bash
# Create an approval keypair — private half 0600, plus an identity-registry member
# (pass --email/--role/--team too, or the member prints REPLACE ME placeholders)
nsauditor-ai compliance keygen --key ~/.nsauditor/approver.pem --approver "Ann Approver"

# Record an approval; SIGNS it when NSAUDITOR_SIGNING_KEY names a local Ed25519 key (verified per approver holding key material)
NSAUDITOR_SIGNING_KEY=~/.nsauditor/approver.pem \
nsauditor-ai compliance suppress --suppressions ./out/suppressions.json \
  --source auth_agent --title-pattern "SSH password authentication enabled" \
  --status accepted_risk --rationale "compensating control at the perimeter" \
  --approver "Ann Approver" --attestation-level approver

# List every approval across a scan history with its expiry status
nsauditor-ai compliance review --history ./out

# Re-approve before expiry (appended to the record's renewals[] chain)
nsauditor-ai compliance renew --suppressions ./out/suppressions.json \
  --id supp-abc123 --rationale "quarterly re-review" --approver "Ann Approver"
```

Three refusals and a warning you will meet rather than a happy path: `keygen` will not overwrite an
existing signing key (every signature it made becomes unverifiable, and nothing says so until an
auditor checks an archived approval); a malformed signing key fails the command and writes
**nothing**; `awskms:` references are refused in this release; and `renew` on a SIGNED approval
**invalidates its signature** — the expiry and the renewal record are inside the signed payload — so
it warns loudly and tells you to re-approve.

⚠️ **`--flag=value` is not supported**, here or on any flag this CLI has: use `--flag value`.
Ed25519 suppression signing is reachable from Enterprise 0.35.0, and **proven at 0.36.0 for approvers whose registry entry carries key material**.
Its verification gate ran against the published bytes and passed, tamper negative control included.
A fingerprint-only registry entry reads `not checked by this report`, which records that no check
ran and never that one failed.
Verification runs for approvers whose registry entry carries key material; a fingerprint-only entry
reads `not checked by this report`, which records that no check ran and never that one failed.

**Compliance evidence (`NSAUDITOR_*` — Enterprise, all opt-in):**

Every variable added from Enterprise 0.33.0 onward carries the `NSAUDITOR_` prefix, so a
deploy can tell at a glance which environment variables belong to this product. The
unprefixed families above (`AI_*`, `OPENAI_*`, `NVD_API_KEY`, `COMPLIANCE_GRC_*`) keep
working exactly as they do today — prefixed aliases arrive in a later minor, and a silent
rename will never happen.

```ini
NSAUDITOR_OFFLINE_ONLY=1          # Exact match on '1'. Forbids outbound: CVE matching reads a local
                                  # NVD store and reports an explicit coverage gap rather than a silent
                                  # clean. Also VETOES the two settings below — configuring an offline
                                  # posture and an outbound destination together is a startup error,
                                  # never a quiet downgrade to weaker evidence.
NSAUDITOR_TSA_URL=                # RFC 3161 Time-Stamp Authority endpoint, opt-in. Proven against a
                                  # live TSA on the npm path AND from inside the :0.33.0 container
                                  # image; :0.32.11 and earlier carry no openssl. NO DEFAULT, EVER —
                                  # unset means the feature is absent, not "use a vendor default".
NSAUDITOR_TSA_CERT_CHAIN=         # Path to the TSA certificate chain (PEM), for offline verification
NSAUDITOR_TSA_POLICY_OID=         # Optional policy OID to request from the TSA
NSAUDITOR_IDENTITY_REGISTRY=      # Path to the approver identity registry JSON. Binds the humans named
                                  # in your suppression file to identities an assessor can check.
                                  # Template ships at data/compliance/identity_registry.json (Enterprise).
NSAUDITOR_SIGNING_KEY=            # A REFERENCE, never key material: keychain:LABEL | /path/to/key.pem
                                  # (mode 0600) | awskms:alias/… — see the honesty note below.
```

Both of these are capabilities now, and each was proven later than it was wired — saying exactly
when, on which delivery vehicle, and for whom is the point:

- **`NSAUDITOR_SIGNING_KEY` is CONSUMED from EE 0.35.0, and the note below used to say otherwise.** EE 0.33.0 stopped parsing it at option-resolution time — a malformed value used to abort the EE stage for a setting nothing read — so it is carried through unparsed; `parseSigningRef` / `resolveSigner` hold the parse and the offline veto at the point a key is used. As of EE 0.35.0 `compliance suppress` signs the approval it writes when this variable names a local Ed25519 key — proven as of EE 0.36.0 and verified per approver holding key material.
  Its verification gate ran against the published bytes and passed, so a produced signature IS
  evidence for those approvers; a fingerprint-only registry entry reads `not checked by this report`. The record's `algorithm` and `backend` fields were frozen *before* the first
  signature could reach a customer archive, because retrofitting that later breaks every
  auditor holding one.
- **`NSAUDITOR_TSA_URL` is wired, and it is proven on both delivery vehicles — the npm path on 2026-08-07, and from inside the `:0.33.0` container image on 2026-08-08.**
  The live check this note used to say was outstanding has been run: through the installed
  binary, against a real Time-Stamp Authority, the auditor procedure `openssl ts -verify`
  returns OK on the compliance report, the scope attestation and the chain of custody; the
  same response file checked against a one-byte-mutated copy of the artifact returns FAILED,
  so the OK is a statement about those exact bytes and not about the command having run.
  ⚠️ The Marketplace container is a second delivery vehicle and was a separate question,
  because the implementation shells out to the `openssl` binary and a distroless runtime
  does not carry one unless it was deliberately put there. **It was deliberately put there
  for `:0.33.0`**: the image now carries the openssl CLI and libs, and a build-blocking gate
  proves it by building a real `openssl ts -query` request through the shipped module INSIDE
  the image before the leg is allowed to push. That check is made by RUNNING the image, never
  by reading the Dockerfile — a negative from a broken probe reads exactly like a negative
  from a missing binary, so the gate exits 2 rather than 1 when its own positive control
  fails. **And the live round-trip has now been run too** (2026-08-08): the shipped signing
  function was driven from inside the pushed `:0.33.0` image against a real authority,
  returning a genuine `.tsr` that the image's own `openssl` verified — with a one-byte-appended
  copy returning FAILED, so the OK is a statement about those bytes rather than about the
  command running. Both delivery vehicles are therefore proven end to end. **The one container
  caveat that survives is version scope:** retained images at `:0.32.11` and earlier do not
  carry the binary at all, so nothing here speaks for them.

**Security overrides:**

```ini
NSA_ALLOW_ALL_HOSTS=1    # Allow scanning private/RFC 1918 ranges (local network auditing)
NSA_AI_TIMEOUT_MS=120000 # AI provider call timeout in ms (default: 120000 = 2 min)
```

**Debug:**

```ini
NSA_VERBOSE=true      # Verbose PluginManager logging
DEBUG_MODE=true       # Plugin-level debug output
```

---

