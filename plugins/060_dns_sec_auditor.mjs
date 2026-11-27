// plugins/060_dns_sec_auditor.mjs
// ─────────────────────────────────────────────────────────────────────────────
// NSAuditor AI – DNS Security Auditor
// Tier: Community (no credentials — just needs DNS resolution)
// Protocol: dns
// ZDE: Queries public DNS records only. No data exfiltrated.
// ─────────────────────────────────────────────────────────────────────────────
//
// What this catches:
//   - Dangling CNAMEs (subdomain takeover risk)
//   - Missing / weak SPF records (+all, ?all, too many lookups, etc.)
//   - Missing / weak DMARC (p=none, missing rua, no subdomain policy)
//   - DKIM selector discovery + key strength
//   - DNSSEC presence / absence
//   - NS delegation hygiene (lame delegation, single NS, private IPs)
//   - Open zone transfers (AXFR)
//   - MX security (missing MX, null MX, MX pointing to IP/CNAME)
//   - CAA record analysis (certificate authority authorization)
//   - Wildcard DNS detection
//
// ─────────────────────────────────────────────────────────────────────────────

import dns from "node:dns/promises";
import dgram from "node:dgram";
import net from "node:net";
import { randomInt } from "node:crypto";
import { classifyAddress, allowAllHosts, isBlockedIp } from "../utils/net_validation.mjs";

// ── Severity ─────────────────────────────────────────────────────────────────

const SEVERITY = Object.freeze({
  CRITICAL: "critical",
  HIGH:     "high",
  MEDIUM:   "medium",
  LOW:      "low",
  INFO:     "info",
  PASS:     "pass",
});

const SEVERITY_RANK = { pass: 0, info: 1, low: 2, medium: 3, high: 4, critical: 5 };

// ── Configuration ────────────────────────────────────────────────────────────
//
//  Optional environment (exported, or in a file passed with --env):
//    DNS_AUDIT_TIMEOUT_MS=5000
//    DNS_AUDIT_DKIM_SELECTORS=google,default,mail,selector1,selector2,s1,s2,k1,k2,k3,dkim,mandrill,mailjet,ses
//    DNS_AUDIT_AXFR_CHECK=true   (opt-in, off by default — see checkAxfr below)
//

function loadConfig(opts = {}) {
  const defaultSelectors = "google,default,mail,selector1,selector2,s1,s2,k1,k2,k3,dkim,mandrill,mailjet,ses,zoho,protonmail,mimecast,mailchimp";
  return {
    timeoutMs: parseInt(opts.timeoutMs || process.env.DNS_AUDIT_TIMEOUT_MS || "5000", 10),
    dkimSelectors: (opts.dkimSelectors || process.env.DNS_AUDIT_DKIM_SELECTORS || defaultSelectors)
      .split(",").map((s) => s.trim()).filter(Boolean),
    // The zone-transfer attempt is OPT-IN (Community 1.0.0): it opens TCP/53 to each nameserver's own address, which comes
    // from the zone's NS records and never from the scan's host check, so neither the pin nor the address-class check
    // governs it. Opt in with DNS_AUDIT_AXFR_CHECK — or a caller's `checkAxfr` option, which wins over it — set to 1, true,
    // yes or on, the convention of every other switch (dns_scanner's DNS_CHECK_AXFR).
    checkAxfr: /^(1|true|yes|on)$/i.test(String(opts.checkAxfr ?? process.env.DNS_AUDIT_AXFR_CHECK ?? "").trim()),
  };
}

// ── Safe DNS Resolve Helpers ─────────────────────────────────────────────────

async function safeResolve(fn, ...args) {
  try {
    return await fn(...args);
  } catch (err) {
    return { error: err.code || err.message };
  }
}

async function resolveTxtFlat(host) {
  const result = await safeResolve(dns.resolveTxt, host);
  if (result?.error) return { records: [], error: result.error };
  return { records: result.flat().map(String), error: null };
}

// A lookup that answered NODATA (ENODATA) or NXDOMAIN (ENOTFOUND) MEASURED an absence. Any other failure — a timeout,
// SERVFAIL, a refused or unreachable resolver, a malformed reply, an error with no code — measured nothing, and must
// never read as the absence: the check it serves is recorded as not measured, with the code, and grades nothing.
const ABSENCE_CODES = new Set(["ENODATA", "ENOTFOUND"]);
const isAbsence = (error) => ABSENCE_CODES.has(error);
const failedToMeasure = (error) => Boolean(error) && !isAbsence(error);

// A not-measured entry carries an error CODE only (G-71 F-060; for every check since VERDICT-v403 R1). `safeResolve` falls
// back to the error's MESSAGE when it has no code, and the entry reaches the reason and a gap row that the md report (and
// MCP scan_host) prints, so anything not code-shaped — a message that only BEGINS with one included — is ENOCODE. Applied
// to every entry at the sort below, the one place they all pass.
const codeOnly = (error) => (typeof error === "string" && /^E[A-Z0-9_]+$/.test(error) ? error : "ENOCODE");

// The checks in the order the result lists them, and their names in the reason a not-measured run carries.
const CHECK_LABELS = [
  ["cname", "CNAME"], ["spf", "SPF"], ["dmarc", "DMARC"], ["dkim", "DKIM"], ["ns", "NS"],
  ["dnssec", "DNSSEC"], ["axfr", "AXFR"], ["mx", "MX"], ["caa", "CAA"], ["wildcard", "wildcard"],
];
const andList = (xs) => (xs.length <= 1 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`);

// The finding ids each check (a key of `findings`, and the `check` of a not-measured record) can emit — for a reader that
// must know which findings a check WOULD have produced when it could not measure it. Held equal, both ways, to each
// check's own `check:` literals by tests/dns_posture_check_ids.test.mjs.
const frozenIds = (...ids) => Object.freeze(ids);
export const CHECK_IDS_BY_CATEGORY = Object.freeze({
  cname: frozenIds("dangling_cname", "takeover_target"),
  spf: frozenIds("missing_spf", "multiple_spf", "spf_plus_all", "spf_neutral_all", "spf_softfail", "spf_hardfail", "spf_no_all",
    "spf_too_many_lookups", "spf_many_lookups", "spf_ptr_deprecated", "spf_broad_ip_range"),
  dmarc: frozenIds("missing_dmarc", "multiple_dmarc", "dmarc_policy_none", "dmarc_policy_quarantine", "dmarc_policy_reject",
    "dmarc_no_subdomain_policy", "dmarc_subdomain_none", "dmarc_low_pct", "dmarc_no_rua", "dmarc_no_ruf",
    "dmarc_relaxed_alignment"),
  dkim: frozenIds("dkim_weak_key", "dkim_short_key", "dkim_testing_mode", "dkim_none_found"),
  ns: frozenIds("no_ns_records", "single_ns", "ns_private_ip", "ns_lame_delegation", "ns_same_subnet"),
  dnssec: frozenIds("no_dnssec", "dnssec_partial", "dnssec_ds_without_dnskey", "dnssec_active"),
  axfr: frozenIds("axfr_open", "axfr_answered_not_transferred"),
  mx: frozenIds("no_mx_a_fallback", "no_mx", "null_mx", "mx_is_ip", "mx_is_cname"),
  caa: frozenIds("no_caa", "caa_present", "caa_no_iodef"),
  wildcard: frozenIds("wildcard_dns"),
});

// The checks that fire once per OBJECT — a CNAME target, an SPF range, a DKIM selector, a nameserver's address, a
// nameserver, an MX host — and the issue field that names it. A comparison keys such a finding on its object as well as
// its check, so a fix on one object and a new exposure on another are two changes, never none. Every other check fires
// once per domain. Held equal, both ways, to the issue literals that carry one of these fields by
// tests/dns_posture_object_identity.test.mjs.
export const CHECK_OBJECT_FIELD = Object.freeze({
  dangling_cname: "target", takeover_target: "target",
  spf_broad_ip_range: "range",
  dkim_weak_key: "selector", dkim_short_key: "selector", dkim_testing_mode: "selector",
  ns_private_ip: "address", ns_lame_delegation: "nameserver",
  axfr_open: "nameserver", axfr_answered_not_transferred: "nameserver",
  mx_is_ip: "exchange", mx_is_cname: "exchange",
});

// The reason a partly measured run reports: which checks were not measured and with which code, and which were. A
// reader that only prints `reason` (a compliance gap row, for one) then still says what the result holds.
function notMeasuredReason(notMeasured, ran) {
  const codeOf = new Map();
  for (const e of notMeasured) if (!codeOf.has(e.check)) codeOf.set(e.check, e.code);
  const byCode = new Map();
  for (const [check, label] of CHECK_LABELS) {
    if (!codeOf.has(check)) continue;
    const code = codeOf.get(check);
    if (!byCode.has(code)) byCode.set(code, []);
    byCode.get(code).push(label);
  }
  const failed = andList([...byCode].map(([code, labels]) => `${labels.join(", ")} (${code})`));
  // Only checks that RAN are named as measured: the opt-in zone transfer, when off, is neither.
  const measured = CHECK_LABELS.filter(([check]) => ran.has(check) && !codeOf.has(check)).map(([, label]) => label);
  const tail = measured.length === 0 ? "no check was measured"
    : `${andList(measured)} ${measured.length === 1 ? "was measured and its findings are" : "were measured and their findings are"} in the result`;
  // A check every entry of which is `partial` (DKIM beside a found selector, G-71 F-060) measured part of what it asks.
  const partial = new Set([...codeOf.keys()].filter((check) => notMeasured.filter((e) => e.check === check).every((e) => e.partial === true)));
  if (partial.size === 0) {
    const notCount = codeOf.size === 1 ? "that check is" : `those ${codeOf.size} checks are`;
    return `resolver failure on ${failed}: ${notCount} not measured; ${tail}`;
  }
  const labelsOf = (pred) => CHECK_LABELS.filter(([check]) => codeOf.has(check) && pred(check)).map(([, label]) => label);
  const full = labelsOf((check) => !partial.has(check));
  const part = labelsOf((check) => partial.has(check));
  const notPart = full.length === 0 ? "" : `${andList(full)} ${full.length === 1 ? "is" : "are"} not measured; `;
  return `resolver failure on ${failed}: ${notPart}${andList(part)} ${part.length === 1 ? "is" : "are"} partly measured — a `
    + `selector lookup that failed measured nothing, and the selectors that answered are in the result; ${tail}`;
}

// ── Module 1: Core Record Collection ─────────────────────────────────────────

async function collectRecords(host) {
  const [a, aaaa, cname, mx, ns, soa, txt, caa] = await Promise.all([
    safeResolve(dns.resolve4, host),
    safeResolve(dns.resolve6, host),
    safeResolve(dns.resolveCname, host),
    safeResolve(dns.resolveMx, host),
    safeResolve(dns.resolveNs, host),
    safeResolve(dns.resolveSoa, host),
    resolveTxtFlat(host),
    safeResolve(dns.resolveCaa, host),
  ]);

  return {
    A:     a?.error     ? null : a,
    AAAA:  aaaa?.error  ? null : aaaa,
    CNAME: cname?.error ? null : (Array.isArray(cname) ? cname : [cname]),
    MX:    mx?.error    ? null : mx,
    NS:    ns?.error    ? null : ns,
    SOA:   soa?.error   ? null : soa,
    TXT:   txt.records,
    CAA:   caa?.error   ? null : caa,
    // Each lookup's error code (null when it answered), so a check can tell a measured absence from a failed lookup.
    errors: {
      A: a?.error ?? null, AAAA: aaaa?.error ?? null, CNAME: cname?.error ?? null, MX: mx?.error ?? null,
      NS: ns?.error ?? null, SOA: soa?.error ?? null, TXT: txt.error ?? null, CAA: caa?.error ?? null,
    },
  };
}

// ── Module 2: Dangling CNAME Detection ───────────────────────────────────────

async function checkDanglingCname(records, host, notMeasured) {
  const issues = [];

  if (failedToMeasure(records.errors.CNAME)) {
    notMeasured.push({ check: "cname", rrtype: "CNAME", name: host, code: records.errors.CNAME });
    return { dangling: false, issues };
  }
  if (!records.CNAME || records.CNAME.length === 0) {
    return { dangling: false, issues };
  }

  for (const target of records.CNAME) {
    const targetStr = String(target);

    // Try both A and AAAA resolution
    const [a4, a6] = await Promise.all([
      safeResolve(dns.resolve4, targetStr),
      safeResolve(dns.resolve6, targetStr),
    ]);

    const a4Failed = a4?.error && isAbsence(a4.error);
    const a6Failed = a6?.error && isAbsence(a6.error);
    // Neither family answered and at least one lookup failed to measure: whether the target dangles is unknown.
    if (a4?.error && a6?.error && !(a4Failed && a6Failed)) {
      const [rrtype, code] = failedToMeasure(a4.error) ? ["A", a4.error] : ["AAAA", a6.error];
      notMeasured.push({ check: "cname", rrtype, name: targetStr, code });
    }

    if (a4Failed && a6Failed) {
      issues.push({
        severity: SEVERITY.CRITICAL,
        check: "dangling_cname",
        detail: `Dangling CNAME: ${targetStr} does not resolve — subdomain takeover possible`,
        target: targetStr,
      });
    }

    // Check for known vulnerable services
    const takeoverTargets = [
      { pattern: /\.s3\.amazonaws\.com$/i,          service: "AWS S3" },
      { pattern: /\.s3-website[.-].*\.amazonaws\.com$/i, service: "AWS S3 Website" },
      { pattern: /\.herokuapp\.com$/i,               service: "Heroku" },
      { pattern: /\.ghost\.io$/i,                    service: "Ghost" },
      { pattern: /\.pantheonsite\.io$/i,             service: "Pantheon" },
      { pattern: /\.shopify\.com$/i,                 service: "Shopify" },
      { pattern: /\.surge\.sh$/i,                    service: "Surge.sh" },
      { pattern: /\.zendesk\.com$/i,                 service: "Zendesk" },
      { pattern: /\.github\.io$/i,                   service: "GitHub Pages" },
      { pattern: /\.gitlab\.io$/i,                   service: "GitLab Pages" },
      { pattern: /\.azurewebsites\.net$/i,           service: "Azure" },
      { pattern: /\.cloudfront\.net$/i,              service: "CloudFront" },
      { pattern: /\.netlify\.(app|com)$/i,           service: "Netlify" },
      { pattern: /\.vercel\.app$/i,                  service: "Vercel" },
      { pattern: /\.fly\.dev$/i,                     service: "Fly.io" },
    ];

    for (const { pattern, service } of takeoverTargets) {
      if (pattern.test(targetStr)) {
        issues.push({
          severity: a4Failed && a6Failed ? SEVERITY.CRITICAL : SEVERITY.MEDIUM,
          check: "takeover_target",
          detail: `CNAME points to ${service} (${targetStr}) — verify ownership is active`,
          target: targetStr,
          service,
        });
        break;
      }
    }
  }

  return { dangling: issues.some((i) => i.check === "dangling_cname"), issues };
}

// ── Module 3: SPF Analysis ───────────────────────────────────────────────────

function analyzeSPF(txtRecords, txtError, host, notMeasured) {
  const issues = [];
  if (failedToMeasure(txtError)) {
    notMeasured.push({ check: "spf", rrtype: "TXT", name: host, code: txtError });
    return { record: null, issues };
  }
  const spfRecords = txtRecords.filter((t) => t.toLowerCase().startsWith("v=spf1"));

  if (spfRecords.length === 0) {
    issues.push({
      severity: SEVERITY.HIGH,
      check: "missing_spf",
      detail: "No SPF record found — domain is vulnerable to email spoofing",
    });
    return { record: null, issues };
  }

  if (spfRecords.length > 1) {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "multiple_spf",
      detail: `Multiple SPF records found (${spfRecords.length}) — only one is valid per RFC 7208`,
    });
  }

  const spf = spfRecords[0];

  // Term-by-term parsing — more precise than regex for qualifier detection
  const terms = spf.trim().split(/\s+/);
  let allQualifier = null;
  let includeCount = 0;
  let redirectCount = 0;

  for (const term of terms) {
    if (term.toLowerCase().startsWith("include:")) includeCount++;
    if (term.toLowerCase().startsWith("redirect=")) redirectCount++;
    if (term.toLowerCase().endsWith("all")) {
      // Qualifier is the first char: +, -, ~, ? (default is + if bare "all")
      const qual = term.length > 3 ? term[0] : "+";
      allQualifier = qual;
    }
  }

  // Policy analysis based on parsed qualifier
  if (allQualifier === "+") {
    issues.push({
      severity: SEVERITY.CRITICAL,
      check: "spf_plus_all",
      detail: 'SPF uses "+all" — permits ALL senders, completely defeats SPF purpose',
    });
  } else if (allQualifier === "?") {
    issues.push({
      severity: SEVERITY.HIGH,
      check: "spf_neutral_all",
      detail: 'SPF uses "?all" (neutral) — does not reject unauthorized senders',
    });
  } else if (allQualifier === "~") {
    issues.push({
      severity: SEVERITY.LOW,
      check: "spf_softfail",
      detail: 'SPF uses "~all" (softfail) — unauthorized mail may still be delivered',
    });
  } else if (allQualifier === "-") {
    issues.push({
      severity: SEVERITY.PASS,
      check: "spf_hardfail",
      detail: 'SPF uses "-all" (hardfail) — good policy',
    });
  } else {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "spf_no_all",
      detail: "SPF record has no all mechanism — behavior is undefined",
    });
  }

  // DNS lookup count — uses both regex (for a/mx/ptr/exists) and term parsing (include/redirect)
  // RFC 7208 counts include, a, mx, ptr, exists, and redirect toward the 10-lookup limit
  const regexLookups = (spf.match(/\b(a|mx|ptr|exists)[\s:\/]/gi) || []).length;
  const totalLookups = includeCount + redirectCount + regexLookups;
  if (totalLookups > 10) {
    issues.push({
      severity: SEVERITY.HIGH,
      check: "spf_too_many_lookups",
      detail: `SPF has ~${totalLookups} DNS lookup mechanisms (RFC 7208 limit: 10) — may cause PermError`,
    });
  } else if (totalLookups > 7) {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "spf_many_lookups",
      detail: `SPF has ~${totalLookups} DNS lookup mechanisms — approaching 10-lookup limit`,
    });
  }

  // Deprecated ptr mechanism
  if (/\bptr\b/i.test(spf)) {
    issues.push({
      severity: SEVERITY.LOW,
      check: "spf_ptr_deprecated",
      detail: 'SPF uses "ptr" mechanism — deprecated per RFC 7208, slow and unreliable',
    });
  }

  // Overly broad ip4/ip6 ranges
  const ipRanges = spf.match(/ip[46]:[^\s]+/gi) || [];
  for (const range of ipRanges) {
    const cidr = range.split("/")[1];
    if (cidr && parseInt(cidr) < 16) {
      issues.push({
        severity: SEVERITY.MEDIUM,
        check: "spf_broad_ip_range",
        detail: `SPF allows very broad IP range: ${range}`,
        range,
      });
    }
  }

  return { record: spf, issues };
}

// ── Module 4: DMARC Analysis ─────────────────────────────────────────────────

async function analyzeDMARC(host, notMeasured) {
  const issues = [];
  const { records, error } = await resolveTxtFlat(`_dmarc.${host}`);
  if (failedToMeasure(error)) {
    notMeasured.push({ check: "dmarc", rrtype: "TXT", name: `_dmarc.${host}`, code: error });
    return { record: null, issues };
  }

  const dmarcRecords = records.filter((t) => t.toLowerCase().startsWith("v=dmarc1"));

  if (dmarcRecords.length === 0) {
    issues.push({
      severity: SEVERITY.HIGH,
      check: "missing_dmarc",
      detail: "No DMARC record found — no protection against email spoofing/phishing",
    });
    return { record: null, issues };
  }

  if (dmarcRecords.length > 1) {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "multiple_dmarc",
      detail: `Multiple DMARC records found (${dmarcRecords.length}) — must have exactly one`,
    });
  }

  const dmarc = dmarcRecords[0];

  // Extract tags
  const tags = {};
  dmarc.split(";").forEach((part) => {
    const [key, ...vals] = part.trim().split("=");
    if (key) tags[key.trim().toLowerCase()] = vals.join("=").trim();
  });

  // Policy analysis
  const policy = (tags.p || "none").toLowerCase();
  if (policy === "none") {
    issues.push({
      severity: SEVERITY.HIGH,
      check: "dmarc_policy_none",
      detail: 'DMARC policy is "none" — monitoring only, no enforcement',
    });
  } else if (policy === "quarantine") {
    issues.push({
      severity: SEVERITY.LOW,
      check: "dmarc_policy_quarantine",
      detail: 'DMARC policy is "quarantine" — consider upgrading to "reject"',
    });
  } else if (policy === "reject") {
    issues.push({
      severity: SEVERITY.PASS,
      check: "dmarc_policy_reject",
      detail: 'DMARC policy is "reject" — strongest enforcement',
    });
  }

  // Subdomain policy — per RFC 7489, sp defaults to p when absent
  const sp = (tags.sp || "").toLowerCase();
  const effectiveSp = sp || policy;  // Inherit from parent if not set

  if (!sp && (policy === "none" || policy === "quarantine")) {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "dmarc_no_subdomain_policy",
      detail: `No explicit DMARC subdomain policy (sp=) — inherits p=${policy} which may be weak for subdomains`,
    });
  } else if (sp === "none") {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "dmarc_subdomain_none",
      detail: 'DMARC subdomain policy is "none" — subdomains can be spoofed',
    });
  }

  // Percentage
  const pct = tags.pct ? parseInt(tags.pct) : 100;
  if (pct < 100) {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "dmarc_low_pct",
      detail: `DMARC pct=${pct}% — only ${pct}% of failing messages are subject to policy`,
    });
  }

  // Reporting
  if (!tags.rua) {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "dmarc_no_rua",
      detail: "No DMARC aggregate report URI (rua=) — you won't see abuse reports",
    });
  }

  if (!tags.ruf) {
    issues.push({
      severity: SEVERITY.INFO,
      check: "dmarc_no_ruf",
      detail: "No DMARC forensic report URI (ruf=) — limited incident visibility",
    });
  }

  // Alignment
  const adkim = (tags.adkim || "r").toLowerCase();
  const aspf = (tags.aspf || "r").toLowerCase();
  if (adkim === "r" || aspf === "r") {
    issues.push({
      severity: SEVERITY.INFO,
      check: "dmarc_relaxed_alignment",
      detail: `DMARC alignment: DKIM=${adkim === "s" ? "strict" : "relaxed"}, SPF=${aspf === "s" ? "strict" : "relaxed"} — consider strict`,
    });
  }

  return { record: dmarc, tags, effectiveSp, issues };
}

// ── Module 5: DKIM Discovery ─────────────────────────────────────────────────

async function discoverDKIM(host, selectors, notMeasured) {
  const issues = [];
  const found = [];
  const failures = [];   // EVERY selector query that failed to measure, in selector order

  for (const selector of selectors) {
    const name = `${selector}._domainkey.${host}`;
    const { records, error } = await resolveTxtFlat(name);
    if (failedToMeasure(error)) failures.push({ name, code: error });
    if (records.length === 0) continue;

    const record = records.join("");
    const entry = { selector, record };

    // Parse key size hint
    const pMatch = record.match(/p=([A-Za-z0-9+/=]+)/);
    if (pMatch) {
      // Base64-encoded public key — length gives rough key size estimate
      const keyB64 = pMatch[1];
      const keyBytes = Math.ceil(keyB64.length * 3 / 4);
      entry.estimatedKeyBits = keyBytes * 8;

      if (keyBytes * 8 < 1024) {
        issues.push({
          severity: SEVERITY.HIGH,
          check: "dkim_weak_key",
          detail: `DKIM selector "${selector}" has a weak key (~${keyBytes * 8} bits) — minimum 1024, recommended 2048`,
          selector,
        });
      } else if (keyBytes * 8 < 2048) {
        issues.push({
          severity: SEVERITY.LOW,
          check: "dkim_short_key",
          detail: `DKIM selector "${selector}" uses ~${keyBytes * 8}-bit key — 2048+ recommended`,
          selector,
        });
      }
    }

    // Check for testing mode
    if (/t=y/i.test(record)) {
      issues.push({
        severity: SEVERITY.MEDIUM,
        check: "dkim_testing_mode",
        detail: `DKIM selector "${selector}" is in testing mode (t=y) — signatures are not enforced`,
        selector,
      });
    }

    found.push(entry);
  }

  // Every failed query is recorded, a selector found or not (G-71 F-060): a row on a selector whose query fails now is
  // then held by the gap instead of reading resolved beside a selector that still answers. Beside a found selector the
  // entry is `partial` — the selectors that answered were measured. "None found" is a measurement only when every
  // selector lookup answered; one that failed might have been the one.
  for (const f of failures) {
    notMeasured.push({ check: "dkim", rrtype: "TXT", name: f.name, code: f.code, ...(found.length > 0 ? { partial: true } : {}) });
  }
  if (found.length === 0 && failures.length === 0) {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "dkim_none_found",
      detail: `No DKIM selectors found among ${selectors.length} common selectors — DKIM may use custom selectors`,
    });
  }

  return { selectors: found, issues };
}

// ── Module 6: NS Delegation Hygiene ──────────────────────────────────────────

async function analyzeNS(records, host, notMeasured) {
  const issues = [];
  const ns = records.NS;
  // A nameserver the public internet cannot reach: an address the shared classifier blocks — loopback, RFC 1918, CGNAT,
  // link-local, unspecified, metadata, unique local — IPv4 or IPv6, in any spelling. One finding per such address.
  const privateAddressIssues = (nsStr, ips) => {
    for (const ip of ips) {
      if (isBlockedIp(ip)) {
        issues.push({
          severity: SEVERITY.HIGH,
          check: "ns_private_ip",
          detail: `Nameserver ${nsStr} resolves to private IP ${ip} — unreachable from public internet`,
          address: ip,
        });
      }
    }
  };

  if (failedToMeasure(records.errors.NS)) {
    notMeasured.push({ check: "ns", rrtype: "NS", name: host, code: records.errors.NS });
    return { nameservers: [], issues };
  }
  if (!ns || ns.length === 0) {
    issues.push({
      severity: SEVERITY.HIGH,
      check: "no_ns_records",
      detail: "No NS records found — DNS resolution may be unreliable",
    });
    return { nameservers: [], issues };
  }

  // Single NS = no redundancy
  if (ns.length === 1) {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "single_ns",
      detail: `Only one nameserver (${ns[0]}) — no redundancy if it goes down`,
    });
  }

  // Check each NS resolves and is not a private IP
  const nsDetails = [];
  for (const nameserver of ns) {
    const nsStr = String(nameserver);
    const entry = { nameserver: nsStr, resolves: false, ips: [] };

    try {
      const ips = await dns.resolve4(nsStr);
      entry.resolves = true;
      entry.ips = ips;

      privateAddressIssues(nsStr, ips);
    } catch (err) {
      const code = err?.code || err?.message;
      // NODATA on A says the name exists with no IPv4 address — it may answer over IPv6. NXDOMAIN answers for every type.
      const v6 = code === "ENODATA" ? await safeResolve(dns.resolve6, nsStr) : null;
      if (v6 && !v6.error) {
        entry.resolves = true;
        entry.ips6 = v6;
        privateAddressIssues(nsStr, v6);
      } else if (isAbsence(code) && (!v6 || isAbsence(v6.error))) {
        issues.push({
          severity: SEVERITY.HIGH,
          check: "ns_lame_delegation",
          detail: `Nameserver ${nsStr} does not resolve — lame delegation`,
          nameserver: nsStr,
        });
      } else {
        // A lookup failed, so whether the nameserver resolves is unknown — never a lame delegation.
        entry.resolves = null;
        const [rrtype, failed] = failedToMeasure(code) ? ["A", code] : ["AAAA", v6.error];
        notMeasured.push({ check: "ns", rrtype, name: nsStr, code: failed });
      }
    }

    nsDetails.push(entry);
  }

  // Check NS diversity (all on same /24?) over the nameservers that RESOLVE to IPv4, when there are at least two of them.
  // A lame nameserver (a measured absence) is excluded and does not block it; one whose address is unknown, or that
  // answers over IPv6 only (its network is not a /24 of these), does — "all in one /24" cannot be said beside it.
  const v4 = nsDetails.filter((n) => n.ips.length > 0);
  const blocked = nsDetails.some((n) => n.resolves === null || (n.ips.length === 0 && (n.ips6?.length ?? 0) > 0));
  const uniqueC = new Set(
    v4.flatMap((n) => n.ips.map((ip) => ip.split(".").slice(0, 3).join(".")))
  );
  if (!blocked && v4.length >= 2 && uniqueC.size === 1) {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "ns_same_subnet",
      // The detail is part of the finding's identity across runs, so it is unchanged unless a nameserver was excluded.
      detail: v4.length === nsDetails.length
        ? "All nameservers are in the same /24 subnet — no network diversity"
        : `The ${v4.length} nameservers that resolve (of ${nsDetails.length}) are all in one /24 subnet — no network diversity`,
    });
  }

  return { nameservers: nsDetails, issues };
}


// ── Module 7: DNSSEC Probe ───────────────────────────────────────────────────
// G-75 (D1). Node's resolver refuses the DNSKEY and DS record types (asked for either, it throws ERR_INVALID_ARG_VALUE
// synchronously), so from Community 1.1.0 to 1.2.0 this check measured no domain at all. It now asks by RAW DNS message.
//
// WHERE IT SENDS: only to the configured resolvers, the entries dns.getServers() returns, in that order — the operator's own
// resolver configuration, and the same servers every resolve* call in this file already uses. A resolver address is
// infrastructure, not scan input: it never comes from the scan target or from any reply. So it does NOT pass the zone
// transfer's address-class gate (classifyAddress, which would refuse the usual resolvers: a private router address, a
// loopback stub resolver), and isBlockedIp is not consulted for it; the scan pin covers dns.lookup for the target's NAME
// only, and a socket to a literal resolver address never calls lookup. Each socket is created inside the run, never at
// module scope. UDP from an UNCONNECTED socket, matched on the reply's source address AND port; TCP only after a reply
// with TC=1. Every socket carries an 'error' listener before its first send and is closed on every path.
//
// WHAT IT READS: presence AS THE CONFIGURED RESOLVER REPORTS IT — RD=1, no EDNS0, no DO bit, the AD bit not read — so no
// signature is validated, and no reply text (an owner name, an error message) reaches a row: rows carry fixed words, the
// target's own name and a suffix of it. A record type is in one state:
//   present = a matched reply, TC=0, NOERROR, an answer record OF THE QUERIED TYPE, and no alias (CNAME/DNAME) in the answer
//   absent  = a matched reply, TC=0, and NXDOMAIN, or NOERROR with no answer record of the queried type and no alias
//   unknown = anything else, with a code: TC=1 with TCP failing (or truncated again), SERVFAIL, REFUSED, FORMERR, NOTIMP,
//             an alias in the answer (ECNAME), no matched reply by the deadline (ETIMEOUT), a reply the parser rejects
//             (EBADRESP), no resolver configured (ENOSERVER) or one whose entry cannot be read (EBADSERVER).
// A reply matches only when its id (crypto randomInt), QR=1, opcode 0 and its ONE question — the name compared
// case-insensitively, the type, the class — echo the query; anything else is ignored and the socket keeps listening.
// Several resolvers: asked in getServers() order, except that the resolver whose reply last DECIDED a query (a walk step
// classified, or a record present or absent) is asked first — so the apex, DNSKEY and DS come from one resolver unless it
// stops answering (then the next is asked, and the probe records how many resolvers decided: details.dnssec.resolverCount,
// never printed in a row). An unknown reply never makes a resolver preferred, and moves the question to the next resolver.
// One UDP attempt with no matched reply is retried ONCE, under a new id, on a new socket (a reply to the first id is not
// read); a resolver whose two attempts both go unanswered, or whose send or socket fails, is skipped for the rest of the
// probe, and the code it failed with is what an all-skipped question reports (the first skipped resolver's). TCP after
// TC=1 is not retried, and its failure does not skip the resolver: that resolver did answer, over UDP.
//
// WHICH ZONE: DNSKEY and DS are asked at the zone APEX, found by a raw SOA walk up the target's labels — the target, then
// each parent, never a single label and never the root, all within ONE deadline shared with the DNSKEY and DS queries
// (DNS_AUDIT_TIMEOUT_MS). A step whose answer holds a CNAME or DNAME is an alias and the walk steps up; an SOA answer with
// no alias is the apex; NOERROR with no answer steps up; NXDOMAIN AT THE TARGET means the check is not measured (one
// ENOTFOUND entry per record type, no row, no walk to the parent — an NXDOMAIN name is not a zone, and the six other checks
// still report absence there, unchanged here); any other outcome is not measured, with its code. A walk that would reach a
// single label — or a single-label target — is not measured, ENOAPEX. Stated limit: a multi-label public suffix is a
// zone and is not caught. An alias's verdict is the zone that holds the alias; the zone it points into is not checked.
//
// Four rows, one per measured cell:
//   absent DNSKEY,  absent DS  → no_dnssec                 (MEDIUM)
//   present DNSKEY, absent DS  → dnssec_partial            (MEDIUM)
//   absent DNSKEY,  present DS → dnssec_ds_without_dnskey  (MEDIUM)
//   present DNSKEY, present DS → dnssec_active             (PASS)
// and an unknown on either side is one not-measured entry per unknown type and NO row; that side's has* is null.
//
// A SERVFAIL VETOES THE PASS (EE VERDICT-v418 C1). A validating resolver's SERVFAIL is the only sign of a bogus chain this
// probe can see, since it validates no signature itself. So when any matched reply the probe read carried rcode 2 in its
// header — a walk step, DNSKEY or DS, at any resolver, over UDP or TCP, with TC=1 or not, and whether or not the rest of
// the reply parses — the dnssec_active cell writes NO row and ONE not-measured entry naming one SERVFAILed query (its
// rrtype and name, code ESERVFAIL), with both has* null. Which query is a function of WHICH questions SERVFAILed, never of
// which reply arrived first: SOA (the first walk step that SERVFAILed), else DNSKEY, else DS (EE VERDICT-v419 G2). The
// three MEDIUM rows stand: they fail toward a finding. Only rcode 2 vetoes — REFUSED, FORMERR, NOTIMP and a timeout do
// not. details.dnssec.servfail says whether any reply was a SERVFAIL, on every return. Stated limits: a resolver later in
// the list is not asked once an earlier one decides, so its SERVFAIL is never seen; and a SERVFAIL that does not echo the
// question (QDCOUNT 0, or another question) is not a matched reply — it is read as silence and does not veto.
//
// Stated limits of the reply reader (parseDnsAnswerTypes): an answer record's owner name and class are not compared with
// the question, and a compression pointer's target is not checked to be a name boundary — only that it points before the
// start of the name it ends. The reader never follows a pointer and skips RDATA, so a loop that runs through an earlier
// record's RDATA (that RDATA pointing forward to a later owner which points back into it) is not seen.

const DNS_QTYPE = Object.freeze({ SOA: 6, DS: 43, DNSKEY: 48 });
const DNS_QTYPE_NAME = Object.freeze(Object.fromEntries(Object.entries(DNS_QTYPE).map(([k, v]) => [v, k])));
const DNS_RCODE_CODE = Object.freeze({ 1: "EFORMERR", 2: "ESERVFAIL", 4: "ENOTIMP", 5: "EREFUSED" });
const ALIAS_TYPES = new Set(["CNAME", "39"]); // 39 = DNAME (parseDnsAnswerTypes names types it does not know by number)
// One UDP or TCP attempt waits min(1999, max(100, floor(timeoutMs / 4))) ms and never past the shared deadline; a reply after
// its window is not read. At most two UDP attempts per resolver per question, so at the default 5000 ms two silent resolvers
// use the whole deadline and a third is never asked (ETIMEOUT).
export function dnsAttemptMs(timeoutMs) {
  return Math.min(1999, Math.max(100, Math.floor(timeoutMs / 4)));
}
const typeNameOf = (qtype) => RR_TYPE_NAME[qtype] ?? String(qtype);

/** One dns.getServers() entry → { family, address, port }, or null. Reads "a.b.c.d", "a.b.c.d:port", "v6" and "[v6]:port". */
export function parseResolverEntry(entry) {
  const s = String(entry ?? "").trim();
  const bracketed = /^\[([^\]]+)\]:(\d+)$/.exec(s);
  const v4WithPort = /^([^:]+):(\d+)$/.exec(s);
  let address;
  let port = 53;
  if (bracketed) { address = bracketed[1]; port = Number(bracketed[2]); }
  else if (net.isIP(s) !== 0) address = s;
  else if (v4WithPort && net.isIP(v4WithPort[1]) === 4) { address = v4WithPort[1]; port = Number(v4WithPort[2]); }
  else return null;
  const family = net.isIP(address);
  if (family === 0 || !Number.isInteger(port) || port < 1 || port > 65535) return null;
  return { family, address, port };
}

/** A query for one question, RD=1, no EDNS0; null for a name that cannot be written as labels. */
function buildDnsQuery(name, qtype, id) {
  const labels = name.split(".");
  if (name.length > 253 || labels.some((l) => !/^[\x21-\x7e]{1,63}$/.test(l))) return null;
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0100, 2);
  header.writeUInt16BE(1, 4);
  const tail = Buffer.alloc(5);
  tail.writeUInt16BE(qtype, 1);
  tail.writeUInt16BE(1, 3);
  return Buffer.concat([header, ...labels.map((l) => Buffer.concat([Buffer.from([l.length]), Buffer.from(l, "ascii")])), tail]);
}

/** Whether a message answers exactly this query: id, QR=1, opcode 0, one question echoing name (any case), type and class. */
function matchesQuery(m, id, name, qtype) {
  if (m.length < 12 || m.readUInt16BE(0) !== id || (m[2] & 0x80) === 0 || ((m[2] >> 3) & 0x0f) !== 0 || m.readUInt16BE(4) !== 1) return false;
  const labels = [];
  let o = 12;
  for (;;) {
    if (o >= m.length) return false;
    const len = m[o];
    if (len === 0) { o += 1; break; }
    if (len > 63 || o + 1 + len > m.length) return false; // a compression pointer in the echoed question is not an echo
    labels.push(m.toString("latin1", o + 1, o + 1 + len).toLowerCase());
    o += 1 + len;
  }
  return o + 4 <= m.length && labels.join(".") === name.toLowerCase() && m.readUInt16BE(o) === qtype && m.readUInt16BE(o + 2) === 1;
}

function udpAttempt(server, query, matches, ctx) {
  const ms = Math.min(ctx.attemptMs, ctx.deadline - Date.now());
  if (ms <= 0) return Promise.resolve({ code: "ETIMEOUT" });
  return new Promise((resolve) => {
    let sock = null;
    let done = false;
    const finish = (r) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { sock?.close(); } catch { /* already closed */ }
      resolve(r);
    };
    const timer = setTimeout(() => finish({ code: "ETIMEOUT" }), ms);
    try {
      sock = dgram.createSocket(server.family === 6 ? "udp6" : "udp4");
      sock.on("error", (err) => finish({ code: err?.code }));
      sock.on("message", (m, rinfo) => {
        if (rinfo.address === server.address && rinfo.port === server.port && matches(m)) finish({ m });
      });
      sock.send(query, server.port, server.address, (err) => { if (err) finish({ code: err.code }); });
    } catch (err) {
      finish({ code: err?.code });
    }
  });
}

function tcpAttempt(server, query, matches, ctx) {
  const ms = Math.min(ctx.attemptMs, ctx.deadline - Date.now());
  if (ms <= 0) return Promise.resolve({ code: "ETIMEOUT" });
  return new Promise((resolve) => {
    let sock = null;
    let done = false;
    let buf = Buffer.alloc(0);
    const finish = (r) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock?.destroy();
      resolve(r);
    };
    const timer = setTimeout(() => finish({ code: "ETIMEOUT" }), ms);
    try {
      sock = net.createConnection({ host: server.address, port: server.port });
      sock.on("error", (err) => finish({ code: err?.code }));
      sock.on("close", () => finish({ code: "ECONNRESET" }));
      sock.on("connect", () => {
        const len = Buffer.alloc(2);
        len.writeUInt16BE(query.length);
        sock.write(Buffer.concat([len, query]));
      });
      sock.on("data", (d) => {
        buf = Buffer.concat([buf, d]);
        while (buf.length >= 2 && buf.length >= 2 + buf.readUInt16BE(0)) {
          const m = buf.subarray(2, 2 + buf.readUInt16BE(0));
          buf = buf.subarray(2 + m.length);
          if (matches(m)) { finish({ m }); return; }
        }
      });
    } catch (err) {
      finish({ code: err?.code });
    }
  });
}

/** rcode, TC and answer types of a matched reply, or { code: "EBADRESP" } when the parser rejects it. */
function readReply(m) {
  try {
    const { rcode, types } = parseDnsAnswerTypes(m);
    return { tc: (m[2] & 0x02) !== 0, rcode, types };
  } catch {
    return { code: "EBADRESP" };
  }
}

/** One question to one resolver: UDP (retried once, under a new id, when no matched reply came back), then TCP iff the UDP
 *  reply has TC=1. → { reply } | { code, skip? } — `skip`: this resolver is skipped for the rest of the probe. */
async function askOneResolver(server, name, qtype, ctx) {
  let udp = null;
  let query = null;
  let matches = null;
  for (let attempt = 0; attempt < 2; attempt++) {
    const id = randomInt(0, 0x10000);
    query = buildDnsQuery(name, qtype, id);
    if (!query) return { code: "EBADNAME" };
    matches = (m) => matchesQuery(m, id, name, qtype);
    udp = await udpAttempt(server, query, matches, ctx);
    if (udp.m || udp.code !== "ETIMEOUT") break; // a send or socket error is not a lost datagram: no retry
  }
  if (!udp.m) return { code: udp.code, skip: true };
  // EE VERDICT-v418 C1: a matched message's rcode is read from its HEADER, whatever else it is — a TC=1 reply (which never
  // decides) and one the parser rejects are still matched replies, and a SERVFAIL among them is kept (`servfail`).
  let servfail = (udp.m[3] & 0x0f) === 2;
  const out = (r) => (servfail ? { ...r, servfail } : r);
  const reply = readReply(udp.m);
  if (reply.code || !reply.tc) return out(reply.code ? { code: reply.code } : { reply });
  // A TC=1 reply never decides, whatever it carries; TCP's reply, matched the same way, is the one read.
  const tcp = await tcpAttempt(server, query, matches, ctx);
  if (!tcp.m) return out({ code: tcp.code });
  servfail ||= (tcp.m[3] & 0x0f) === 2;
  const again = readReply(tcp.m);
  if (again.code) return out({ code: again.code });
  return out(again.tc ? { code: "ETRUNCATED" } : { reply: again });
}

/** Asks the configured resolvers — the preferred one first, then getServers() order; `decide(reply)` → { state, code? }.
 *  An unknown moves to the next resolver; the first decision returns, and makes its resolver the preferred one. */
async function askResolvers(name, qtype, ctx, decide) {
  const configured = dns.getServers();
  if (configured.length === 0) return { state: "unknown", code: "ENOSERVER" };
  const entries = ctx.preferred && configured.includes(ctx.preferred)
    ? [ctx.preferred, ...configured.filter((e) => e !== ctx.preferred)] : configured;
  let first = null;
  for (const entry of entries) {
    if (ctx.skipped.has(entry)) { first ??= { state: "unknown", code: ctx.skipped.get(entry) }; continue; }
    const server = parseResolverEntry(entry);
    const r = server ? await askOneResolver(server, name, qtype, ctx) : { code: "EBADSERVER", skip: true };
    if (r.skip) ctx.skipped.set(entry, r.code);
    // EE VERDICT-v418 C1: the first question a matched reply SERVFAILed is kept — it vetoes dnssec_active (probeDNSSEC).
    if (r.servfail) ctx.servfail[DNS_QTYPE_NAME[qtype]] ??= name;
    const out = r.reply ? decide(r.reply) : { state: "unknown", code: r.code };
    if (out.state !== "unknown") {
      ctx.preferred = entry;
      ctx.deciders.add(entry);
      return out;
    }
    first ??= out;
  }
  return first;
}

const decideRecord = (qtype) => ({ rcode, types }) => {
  if (rcode === 3) return { state: "absent" };
  if (rcode !== 0) return { state: "unknown", code: DNS_RCODE_CODE[rcode] ?? `ERCODE${rcode}` };
  if (types.some((t) => ALIAS_TYPES.has(t))) return { state: "unknown", code: "ECNAME" };
  return { state: types.includes(typeNameOf(qtype)) ? "present" : "absent" };
};
const decideWalkStep = ({ rcode, types }) => {
  if (rcode === 3) return { state: "nxdomain" };
  if (rcode !== 0) return { state: "unknown", code: DNS_RCODE_CODE[rcode] ?? `ERCODE${rcode}` };
  if (types.some((t) => ALIAS_TYPES.has(t))) return { state: "alias" };
  if (types.includes("SOA")) return { state: "apex" };
  return types.length === 0 ? { state: "nodata" } : { state: "unknown", code: "EBADRESP" };
};

/** The raw SOA walk. → { apex, alias } | { notMeasured: [{ rrtype, name, code }] } */
async function findZoneApex(target, ctx) {
  const labels = target.split(".");
  // A single-label target asks nothing: the loop below never runs and the walk ends in ENOAPEX (W5).
  let alias = false;
  for (let i = 0; i < labels.length - 1; i++) {
    const name = labels.slice(i).join(".");
    const step = await askResolvers(name, DNS_QTYPE.SOA, ctx, decideWalkStep);
    if (step.state === "apex") return { apex: name, alias };
    if (step.state === "alias" || step.state === "nodata") { if (i === 0) alias = step.state === "alias"; continue; }
    if (step.state === "nxdomain" && i === 0) {
      // NXDOMAIN at the target: not measured, by its own code. Never through isAbsence — an NXDOMAIN name is not a zone.
      return { notMeasured: ["DNSKEY", "DS"].map((rrtype) => ({ rrtype, name: target, code: "ENOTFOUND" })) };
    }
    return { notMeasured: [{ rrtype: "SOA", name, code: step.state === "nxdomain" ? "ENOTFOUND" : step.code }] };
  }
  return { notMeasured: [{ rrtype: "SOA", name: target, code: "ENOAPEX" }] };
}

/** The decision over both record types' states — all nine cells. → { row, hasDNSKEY, hasDS, unknown: [{ rrtype, code }] } */
export function dnssecOutcome(dnskey, ds) {
  const has = (s) => (s.state === "present" ? true : s.state === "absent" ? false : null);
  const hasDNSKEY = has(dnskey);
  const hasDS = has(ds);
  const unknown = [["DNSKEY", dnskey], ["DS", ds]].filter(([, s]) => has(s) === null).map(([rrtype, s]) => ({ rrtype, code: s.code }));
  if (unknown.length > 0) return { row: null, hasDNSKEY, hasDS, unknown };
  const row = hasDNSKEY ? (hasDS ? "dnssec_active" : "dnssec_partial") : (hasDS ? "dnssec_ds_without_dnskey" : "no_dnssec");
  return { row, hasDNSKEY, hasDS, unknown };
}

/** The SERVFAIL the entry names: SOA, then DNSKEY, then DS — a function of WHICH questions SERVFAILed, never of which reply
 *  arrived first (DNSKEY and DS are asked in parallel; EE VERDICT-v419 G2). The walk is sequential, so the SOA name kept is
 *  the first step that SERVFAILed. → { rrtype, name } | null */
function firstServfail(ctx) {
  for (const rrtype of ["SOA", "DNSKEY", "DS"]) if (ctx.servfail[rrtype] !== undefined) return { rrtype, name: ctx.servfail[rrtype] };
  return null;
}

/** The zone a row names, in fixed words around the target's own name and a suffix of it. */
function dnssecZoneWords(target, apex, alias) {
  const zone = apex === target ? `the zone ${apex}` : `the zone ${apex}, which holds ${target}`;
  return alias ? `${zone} (${target} is an alias (CNAME); the zone it points into was not checked)` : zone;
}

export async function probeDNSSEC(host, notMeasured, config = loadConfig()) {
  const issues = [];
  const target = String(host).replace(/\.$/, "").toLowerCase();
  const ctx = {
    deadline: Date.now() + config.timeoutMs,
    attemptMs: dnsAttemptMs(config.timeoutMs),
    skipped: new Map(),
    preferred: null,
    deciders: new Set(),
    servfail: {}, // rrtype → name of the first question of that type a matched reply SERVFAILed (askResolvers)
  };
  const walk = await findZoneApex(target, ctx);
  if (walk.notMeasured) {
    for (const e of walk.notMeasured) notMeasured.push({ check: "dnssec", rrtype: e.rrtype, name: e.name, code: e.code });
    return { hasDNSKEY: null, hasDS: null, zone: null, alias: false, resolverCount: ctx.deciders.size, servfail: firstServfail(ctx) !== null, issues };
  }
  const { apex, alias } = walk;
  const [dnskey, ds] = await Promise.all([
    askResolvers(apex, DNS_QTYPE.DNSKEY, ctx, decideRecord(DNS_QTYPE.DNSKEY)),
    askResolvers(apex, DNS_QTYPE.DS, ctx, decideRecord(DNS_QTYPE.DS)),
  ]);
  const outcome = dnssecOutcome(dnskey, ds);
  const servfail = firstServfail(ctx);
  if (outcome.row === "dnssec_active" && servfail !== null) {
    // EE VERDICT-v418 C1: a PASS is never written over a SERVFAIL the probe read — no row, ONE entry naming that query.
    notMeasured.push({ check: "dnssec", rrtype: servfail.rrtype, name: servfail.name, code: "ESERVFAIL" });
    return { hasDNSKEY: null, hasDS: null, zone: apex, alias, resolverCount: ctx.deciders.size, servfail: true, issues };
  }
  for (const u of outcome.unknown) notMeasured.push({ check: "dnssec", rrtype: u.rrtype, name: apex, code: u.code });
  const where = dnssecZoneWords(target, apex, alias);
  const reported = "as reported by the configured resolver; signatures not validated";
  if (outcome.row === "no_dnssec") {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "no_dnssec",
      detail: `No DNSKEY or DS records for ${where}, ${reported} — DNS responses for this zone are not signed and can be spoofed`,
    });
  } else if (outcome.row === "dnssec_partial") {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "dnssec_partial",
      detail: `DNSKEY records but no DS record for ${where}, ${reported} — the chain of trust is not established`,
    });
  } else if (outcome.row === "dnssec_ds_without_dnskey") {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "dnssec_ds_without_dnskey",
      detail: `A DS record but no DNSKEY records for ${where}, ${reported} — the parent zone points at keys this zone does not publish`,
    });
  } else if (outcome.row === "dnssec_active") {
    issues.push({
      severity: SEVERITY.PASS,
      check: "dnssec_active",
      detail: `DNSKEY and DS records present for ${where}, ${reported}`,
    });
  }
  return { hasDNSKEY: outcome.hasDNSKEY, hasDS: outcome.hasDS, zone: apex, alias, resolverCount: ctx.deciders.size, servfail: servfail !== null, issues };
}

// ── Module 8: Zone Transfer Check (AXFR) ────────────────────────────────────
// An open zone transfer is a critical finding — it dumps the entire zone.

async function checkZoneTransfer(host, nameservers, config, notMeasured) {
  const issues = [];

  if (!config.checkAxfr) return { issues, tested: "opt-in-off" };
  if (nameservers.length === 0) return { issues, tested: "no-nameservers" };

  // Every nameserver carries a record once the check is on — attempted with what it answered, or not attempted with why —
  // so an empty finding list never has to stand in for "refused" or "not asked".
  const attempts = [];
  for (const ns of nameservers) {
    if (ns.resolves === null) { ns.axfr = { attempted: false, reason: "address-unknown" }; continue; }
    if (!ns.resolves) { ns.axfr = { attempted: false, reason: "does-not-resolve" }; continue; }
    if (ns.ips.length === 0) { ns.axfr = { attempted: false, reason: "no-ipv4-address" }; continue; }

    const ip = ns.ips[0];
    // The address comes from the zone's own NS records, which no host check looked at: classify the literal that would
    // be connected, with the classifier every other connect uses. `always` (loopback, link-local and metadata, the
    // unspecified address) is refused in every configuration; `private` unless NSA_ALLOW_ALL_HOSTS is set. A refusal is
    // recorded on the nameserver, never graded, and there is no fall-through to another answer.
    const addressClass = classifyAddress(ip);
    if (addressClass === "always" || (addressClass === "private" && !allowAllHosts())) {
      ns.axfr = { attempted: false, reason: "address-refused", addressClass, address: ip, answers: ns.ips.length };
      continue;
    }
    const measured = attemptAXFR(host, ip, config.timeoutMs);
    // A throw still fails the run when its turn is read below, as it did one attempt at a time; until then it is
    // handled, so a later attempt's failure is never an unhandled rejection while an earlier one is still waiting.
    measured.catch(() => {});
    attempts.push({ ns, ip, measured });
  }

  // The attempts run together, so nameservers that never answer cost one timeout rather than one each; each result is
  // read back against its own nameserver, in the zone's order.
  for (const { ns, ip, measured: pending } of attempts) {
    const measured = await pending;
    ns.axfr = { attempted: true, address: ip, ...measured };

    // The detail is the finding's identity across runs (the history delta and Enterprise both key it), so it names the
    // nameserver and nothing that moves with the zone: what the answer carried is evidence ON the finding. axfr_open's
    // wording is the one earlier releases wrote, so an open transfer stays the same finding across the upgrade.
    if (measured.outcome === "transferred") {
      issues.push({
        severity: SEVERITY.CRITICAL,
        check: "axfr_open",
        detail: `Zone transfer (AXFR) allowed on ${ns.nameserver} (${ip}) — entire zone is exposed`,
        nameserver: ns.nameserver,
        records: measured.records,
        complete: measured.complete,
      });
    } else if (measured.outcome === "answered-not-transferred") {
      issues.push({
        severity: SEVERITY.LOW,
        check: "axfr_answered_not_transferred",
        detail: `Nameserver ${ns.nameserver} (${ip}) answers zone-transfer (AXFR) queries instead of refusing them — no zone was transferred`,
        nameserver: ns.nameserver,
        records: measured.records,
        firstType: measured.firstType,
      });
    } else if (measured.outcome === "no-answer") {
      notMeasured.push({ check: "axfr", rrtype: "AXFR", name: ns.nameserver, code: measured.code });
    }
  }

  return { issues, tested: true };
}

// DNS record types the zone-transfer verdict names.
const RR_TYPE_NAME = { 1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 257: "CAA" };
/** The RCODE and the answer records' types, in order, of one DNS message (no TCP length prefix). Throws on a malformed one.
 *  It never follows a compression pointer (a pointer ends a name), so a pointer loop cannot hold it. Since G-75 it also reads
 *  replies from the configured resolver, not only from a nameserver the operator opted in to. Stated limits: an answer
 *  record's owner name and class are not compared with the question, and a pointer's target is not checked to be a name
 *  boundary. */
export function parseDnsAnswerTypes(m) {
  if (m.length < 12) throw new Error("short header");
  const rcode = m.readUInt8(3) & 0x0f;
  const qd = m.readUInt16BE(4);
  const an = m.readUInt16BE(6);
  const skipName = (at) => {
    for (let o = at; ;) {
      if (o >= m.length) throw new Error("name past end");
      const len = m.readUInt8(o);
      if (len === 0) return o + 1;
      if ((len & 0xc0) === 0xc0) {
        if (o + 2 > m.length) throw new Error("pointer past end");
        // A pointer names an EARLIER occurrence (RFC 1035 4.1.4): it must point before the start of the name it ends.
        // One that points at that start, inside the name (a label, then a pointer back to the label) or forward is a loop
        // or a forgery, even though this reader never follows it (EE VERDICT-v418 C2: bounding it at the pointer instead
        // let `01 61 C0 <start of this name>` through). Stated limit: the target is not checked to be a name boundary.
        const target = ((len & 0x3f) << 8) | m.readUInt8(o + 1);
        if (target < 12 || target >= at) throw new Error("pointer not before the name");
        return o + 2;
      }
      if ((len & 0xc0) !== 0) throw new Error("reserved label type");
      o += 1 + len;
    }
  };
  let off = 12;
  for (let i = 0; i < qd; i++) off = skipName(off) + 4;
  const types = [];
  for (let i = 0; i < an; i++) {
    off = skipName(off);
    if (off + 10 > m.length) throw new Error("record header past end");
    const type = m.readUInt16BE(off);
    const rdlen = m.readUInt16BE(off + 8);
    off += 10 + rdlen;
    if (off > m.length) throw new Error("record data past end");
    types.push(RR_TYPE_NAME[type] ?? String(type));
  }
  return { rcode, types };
}

// The zone-transfer attempt, MEASURED: what the nameserver answered, read message by message, never a guess from the
// first chunk's length.
//   transferred               RCODE 0, the answer opens with the zone's SOA and carries more records — zone data left the
//                             server (`complete` when the closing SOA arrived; a cut transfer still leaked what it sent);
//   answered-not-transferred  RCODE 0 with anything else — an SOA alone, or another first record: no zone came back;
//   refused                   an error RCODE (REFUSED, NOTAUTH, SERVFAIL, …), or TCP/53 refused the connection;
//   no-answer                 a timeout, a transport error, a reply cut short or unparseable — nothing was measured.
const MAX_AXFR_RECORDS = 10000;
function attemptAXFR(domain, nsIP, timeoutMs) {
  return new Promise((resolve) => {
    let done = false;
    let answered = false;           // a complete RCODE-0 message arrived
    let buf = Buffer.alloc(0);
    const types = [];
    const verdict = (complete) => (types[0] === "SOA" && types.length > 1
      ? { outcome: "transferred", records: types.length, firstType: "SOA", complete }
      : { outcome: "answered-not-transferred", records: types.length, firstType: types[0] ?? null });
    const finish = (r) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      try { socket.destroy(); } catch { /* already gone */ }
      resolve(r);
    };
    const timer = setTimeout(() => finish(answered ? verdict(false) : { outcome: "no-answer", code: "ETIMEOUT" }), timeoutMs);

    const socket = net.createConnection({ host: nsIP, port: 53 }, () => {
      // Build a minimal AXFR query
      const query = buildAXFRQuery(domain);
      // TCP DNS: 2-byte length prefix
      const lenBuf = Buffer.alloc(2);
      lenBuf.writeUInt16BE(query.length);
      socket.write(Buffer.concat([lenBuf, query]));
    });

    socket.on("data", (data) => {
      buf = Buffer.concat([buf, data]);
      while (buf.length >= 2) {
        const len = buf.readUInt16BE(0);
        if (buf.length < 2 + len) break;
        const msg = buf.subarray(2, 2 + len);
        buf = buf.subarray(2 + len);
        let parsed;
        try { parsed = parseDnsAnswerTypes(msg); } catch { return finish({ outcome: "no-answer", code: "EBADRESP" }); }
        if (parsed.rcode !== 0) return finish({ outcome: "refused", rcode: parsed.rcode });
        answered = true;
        types.push(...parsed.types);
        // The closing SOA ends a transfer; a cap bounds a hostile one.
        if (types.length > 1 && types[0] === "SOA" && types[types.length - 1] === "SOA") return finish(verdict(true));
        if (types.length > MAX_AXFR_RECORDS) return finish(verdict(false));
      }
    });

    socket.on("error", (err) => {
      const code = err?.code || "ESOCKET";
      finish(code === "ECONNREFUSED" ? { outcome: "refused", code } : answered ? verdict(false) : { outcome: "no-answer", code });
    });

    socket.on("close", () => {
      finish(answered ? verdict(false) : { outcome: "no-answer", code: "ECLOSED" });
    });
  });
}

function buildAXFRQuery(domain) {
  // DNS query header
  const header = Buffer.alloc(12);
  header.writeUInt16BE(0x1234, 0);  // Transaction ID
  header.writeUInt16BE(0x0000, 2);  // Standard query
  header.writeUInt16BE(1, 4);       // Questions: 1
  header.writeUInt16BE(0, 6);       // Answer RRs
  header.writeUInt16BE(0, 8);       // Authority RRs
  header.writeUInt16BE(0, 10);      // Additional RRs

  // Question section: domain name + type AXFR (252) + class IN (1)
  const labels = domain.split(".").map((label) => {
    const buf = Buffer.alloc(1 + label.length);
    buf.writeUInt8(label.length, 0);
    buf.write(label, 1, "ascii");
    return buf;
  });
  const terminator = Buffer.alloc(1); // null label
  const qtype = Buffer.alloc(2);
  qtype.writeUInt16BE(252); // AXFR
  const qclass = Buffer.alloc(2);
  qclass.writeUInt16BE(1);  // IN

  return Buffer.concat([header, ...labels, terminator, qtype, qclass]);
}

// ── Module 9: MX Security ────────────────────────────────────────────────────

async function analyzeMX(records, host, notMeasured) {
  const issues = [];
  const mx = records.MX;

  if (failedToMeasure(records.errors.MX)) {
    notMeasured.push({ check: "mx", rrtype: "MX", name: host, code: records.errors.MX });
    return { mxRecords: [], issues };
  }
  if (!mx || mx.length === 0) {
    // Check for null MX (RFC 7505)
    const { records: txtRecs } = await resolveTxtFlat(host);
    // With no A or AAAA answer, "no fallback" is a measurement only when neither lookup failed to measure.
    if (!records.A && !records.AAAA && (failedToMeasure(records.errors.A) || failedToMeasure(records.errors.AAAA))) {
      const [rrtype, code] = failedToMeasure(records.errors.A) ? ["A", records.errors.A] : ["AAAA", records.errors.AAAA];
      notMeasured.push({ check: "mx", rrtype, name: host, code });
      return { mxRecords: [], issues };
    }
    // A domain with no MX might use A/AAAA fallback (bad practice)
    if (records.A || records.AAAA) {
      issues.push({
        severity: SEVERITY.LOW,
        check: "no_mx_a_fallback",
        detail: "No MX records — mail delivery will fall back to A/AAAA records (not recommended)",
      });
    } else {
      issues.push({
        severity: SEVERITY.INFO,
        check: "no_mx",
        detail: "No MX records and no A/AAAA — domain does not receive email",
      });
    }
    return { mxRecords: [], issues };
  }

  // Null MX check (priority 0, exchange ".")
  const hasNullMX = mx.some((m) => m.priority === 0 && (m.exchange === "." || m.exchange === ""));
  if (hasNullMX) {
    issues.push({
      severity: SEVERITY.PASS,
      check: "null_mx",
      detail: "Null MX record present (RFC 7505) — domain explicitly does not accept mail",
    });
    return { mxRecords: mx, issues };
  }

  for (const m of mx) {
    const exchange = String(m.exchange);

    // MX pointing to IP address (forbidden per RFC 5321)
    if (net.isIP(exchange)) {
      issues.push({
        severity: SEVERITY.MEDIUM,
        check: "mx_is_ip",
        detail: `MX record points to IP address ${exchange} (priority ${m.priority}) — violates RFC 5321`,
        exchange,
      });
    }

    // MX pointing to CNAME (also bad practice)
    const cnameCheck = await safeResolve(dns.resolveCname, exchange);
    if (failedToMeasure(cnameCheck?.error)) {
      notMeasured.push({ check: "mx", rrtype: "CNAME", name: exchange, code: cnameCheck.error });
    } else if (!cnameCheck?.error) {
      issues.push({
        severity: SEVERITY.MEDIUM,
        check: "mx_is_cname",
        detail: `MX ${exchange} is a CNAME — violates RFC 2181, may cause delivery issues`,
        exchange,
      });
    }
  }

  return { mxRecords: mx, issues };
}

// ── Module 10: CAA Records ───────────────────────────────────────────────────

function analyzeCAA(records, host, notMeasured) {
  const issues = [];
  const caa = records.CAA;

  if (failedToMeasure(records.errors.CAA)) {
    notMeasured.push({ check: "caa", rrtype: "CAA", name: host, code: records.errors.CAA });
    return { records: [], issues };
  }
  if (!caa || caa.length === 0) {
    issues.push({
      severity: SEVERITY.LOW,
      check: "no_caa",
      detail: "No CAA records — any CA can issue certificates for this domain",
    });
    return { records: [], issues };
  }

  // node's resolveCaa keys each record by its TAG — `{ critical, type: 'CAA', issue: 'pki.goog' }`, `issuewild`, `iodef`
  // — with no `tag` or `value` field.
  const issueValues = caa.flatMap((r) => ["issue", "issuewild"].filter((t) => typeof r?.[t] === "string").map((t) => r[t]));

  if (issueValues.length > 0) {
    issues.push({
      severity: SEVERITY.PASS,
      check: "caa_present",
      detail: `CAA records restrict certificate issuance to: ${issueValues.join(", ")}`,
    });
  }

  // Check for iodef (incident reporting)
  const iodef = caa.find((r) => typeof r?.iodef === "string");
  if (!iodef) {
    issues.push({
      severity: SEVERITY.INFO,
      check: "caa_no_iodef",
      detail: "No CAA iodef tag — CA policy violation reports won't be sent",
    });
  }

  return { records: caa, issues };
}

// ── Module 11: Wildcard DNS Detection ────────────────────────────────────────

async function checkWildcard(host, notMeasured) {
  const issues = [];
  const randomSub = `nsauditor-wildcard-probe-${Date.now()}.${host}`;

  const result = await safeResolve(dns.resolve4, randomSub);
  if (failedToMeasure(result?.error)) {
    notMeasured.push({ check: "wildcard", rrtype: "A", name: randomSub, code: result.error });
  } else if (!result?.error) {
    issues.push({
      severity: SEVERITY.LOW,
      check: "wildcard_dns",
      detail: `Wildcard DNS detected — random subdomain resolves to ${result.join(", ")}`,
    });
  }

  return { issues };
}

// ── Plugin Export ─────────────────────────────────────────────────────────────

// The conclude line's DNSSEC words, one per row (G-75 G4, G12): fixed words, the measured zone, the alias note.
const DNSSEC_CONCLUDE_WORDS = Object.freeze({
  dnssec_active: "DNSSEC active", dnssec_partial: "DNSSEC partial: DNSKEY without DS",
  dnssec_ds_without_dnskey: "DNSSEC: DS without DNSKEY", no_dnssec: "no DNSSEC",
});
function dnssecConcludeWords(result) {
  const row = (result.findings?.dnssec ?? []).find((i) => Object.hasOwn(DNSSEC_CONCLUDE_WORDS, i.check))?.check;
  const { zone, alias } = result.details?.dnssec ?? {};
  if (!row) return "DNSSEC not measured";
  return `${DNSSEC_CONCLUDE_WORDS[row]} (zone ${zone}${alias ? "; the name is an alias (CNAME), the zone it points into was not checked" : ""})`;
}

export default {
  id: "060",
  name: "DNS Security Auditor",
  description:
    "Audits DNS posture: SPF/DKIM/DMARC email security, dangling CNAMEs, DNSSEC, " +
    "NS delegation hygiene, zone transfer exposure, MX security, CAA records, and wildcard DNS.",
  priority: 220,
  tier: "community",
  protocols: ["dns"],
  ports: [],

  requirements: {},

  preflight() {
    return { ready: true };
  },

  // ── Main Execution ──────────────────────────────────────────────────────
  async run(host, port, opts = {}) {
    // 0.2.57: an IP LITERAL is DECLINED, with its reason on the plugin's status. Queried as a name it answers NXDOMAIN to
    // every record type, and each absence became a finding (missing SPF / DMARC / NS at HIGH) on every default scan of
    // an address. Only the literal is declined: a hostname that resolves to an address — localhost too — is a domain.
    if (net.isIP(String(host)) !== 0) {
      return { up: false, skipped: true,
        reason: `DNS posture needs a domain name — ${host} is an IP address, which has no SPF, DMARC or NS records to audit` };
    }
    const config = loadConfig(opts);
    const startTime = Date.now();

    // 1. Collect all DNS records
    const records = await collectRecords(host);

    // 2. Run all analysis modules. Each records the lookups that failed to MEASURE (anything but NODATA / NXDOMAIN) in
    // `notMeasured` and grades nothing from them; the list is sorted into the result's check order below.
    const notMeasured = [];
    const [cname, spf, dmarc, dkim, nsCheck, dnssec, mx, caa, wildcard] = await Promise.all([
      checkDanglingCname(records, host, notMeasured),
      Promise.resolve(analyzeSPF(records.TXT, records.errors.TXT, host, notMeasured)),
      analyzeDMARC(host, notMeasured),
      discoverDKIM(host, config.dkimSelectors, notMeasured),
      analyzeNS(records, host, notMeasured),
      probeDNSSEC(host, notMeasured, config),
      analyzeMX(records, host, notMeasured),
      Promise.resolve(analyzeCAA(records, host, notMeasured)),
      checkWildcard(host, notMeasured),
    ]);
    // 3. Zone transfer check (depends on NS results; opt-in) — it records its own not-measured nameservers too.
    const axfr = await checkZoneTransfer(host, nsCheck.nameservers, config, notMeasured);
    const checkOrder = new Map(CHECK_LABELS.map(([check], i) => [check, i]));
    notMeasured.sort((x, y) => checkOrder.get(x.check) - checkOrder.get(y.check));
    for (const e of notMeasured) e.code = codeOnly(e.code);
    const ran = new Set(CHECK_LABELS.map(([check]) => check).filter((check) => check !== "axfr" || config.checkAxfr));

    // Aggregate all issues
    const allIssues = [
      ...cname.issues,
      ...spf.issues,
      ...dmarc.issues,
      ...dkim.issues,
      ...nsCheck.issues,
      ...dnssec.issues,
      ...axfr.issues,
      ...mx.issues,
      ...caa.issues,
      ...wildcard.issues,
    ];

    // Overall severity
    let overallSeverity = SEVERITY.PASS;
    for (const issue of allIssues) {
      if (SEVERITY_RANK[issue.severity] > SEVERITY_RANK[overallSeverity]) {
        overallSeverity = issue.severity;
      }
    }

    // Summary counts
    const actionable = allIssues.filter((i) =>
      i.severity !== SEVERITY.PASS && i.severity !== SEVERITY.INFO
    );

    const summary = {
      totalChecks: allIssues.length,
      actionable: actionable.length,
      critical: allIssues.filter((i) => i.severity === SEVERITY.CRITICAL).length,
      high:     allIssues.filter((i) => i.severity === SEVERITY.HIGH).length,
      medium:   allIssues.filter((i) => i.severity === SEVERITY.MEDIUM).length,
      low:      allIssues.filter((i) => i.severity === SEVERITY.LOW).length,
      info:     allIssues.filter((i) => i.severity === SEVERITY.INFO).length,
      pass:     allIssues.filter((i) => i.severity === SEVERITY.PASS).length,
      notMeasured: notMeasured.length,
    };

    // A run that could not measure every check is not up, and carries a reason naming what it did and did not measure, so a
    // reader that only sees `up` holds this audit's results as a gap rather than as a clean domain. It is never
    // `skipped` (that is the declined-address case above), and the checks it DID measure keep their findings.
    return {
      up: notMeasured.length === 0,
      ...(notMeasured.length > 0 ? { reason: notMeasuredReason(notMeasured, ran) } : {}),
      audit_type: "dns_security",
      host,
      overallSeverity,
      duration_ms: Date.now() - startTime,
      summary,
      records: {
        A: records.A,
        AAAA: records.AAAA,
        CNAME: records.CNAME,
        MX: records.MX,
        NS: records.NS,
        hasSOA: failedToMeasure(records.errors.SOA) ? null : !!records.SOA,
        txtCount: records.TXT.length,
        caaCount: (records.CAA || []).length,
      },
      findings: {
        cname:  cname.issues,
        spf:    spf.issues,
        dmarc:  dmarc.issues,
        dkim:   dkim.issues,
        ns:     nsCheck.issues,
        dnssec: dnssec.issues,
        axfr:   axfr.issues,
        mx:     mx.issues,
        caa:    caa.issues,
        wildcard: wildcard.issues,
      },
      details: {
        spfRecord: spf.record,
        dmarcRecord: dmarc.record,
        dmarcTags: dmarc.tags || null,
        dkimSelectors: dkim.selectors,
        nameservers: nsCheck.nameservers,
        mxRecords: mx.mxRecords,
        dnssec: { hasDNSKEY: dnssec.hasDNSKEY, hasDS: dnssec.hasDS, zone: dnssec.zone, alias: dnssec.alias, resolverCount: dnssec.resolverCount, servfail: dnssec.servfail },
        // The zone-transfer check: true when it ran, else why it did not ('opt-in-off', 'no-nameservers').
        axfrTested: axfr.tested,
        notMeasured,
      },
    };
  },

  // ── Conclude ────────────────────────────────────────────────────────────
  // 1.3.0: ONE record, its findings under `dnsSecurity`, ATTACH-ONLY. This audits a domain's DNS posture and runs on
  // every scan, so it is not a port on the scanned host: it lands on a 53/udp record a port-level probe found, and
  // otherwise becomes evidence. Its per-finding records carried NO port (they keyed to `dns:NaN`), and the summary
  // wrote "DNS-Audit" / "v2" into identity and its verdict into the liveness field.
  conclude({ result, host }) {
    if (!result.findings) return [];

    const findings = Object.entries(result.findings)
      .flatMap(([category, issues]) => issues.map((i) => ({ ...i, category })))
      .filter((f) => f.severity !== SEVERITY.PASS && f.severity !== SEVERITY.INFO)
      .map((f) => {
        // A per-object finding carries its object, so a comparison can tell one nameserver's finding from another's.
        const object = Object.hasOwn(CHECK_OBJECT_FIELD, f.check) ? f[CHECK_OBJECT_FIELD[f.check]] : undefined;
        return { severity: f.severity, category: f.category, check: f.check, detail: f.detail,
          ...(object != null && object !== "" ? { object: String(object) } : {}) };
      });
    // The nameservers whose zone transfer was not attempted, in their own order — a record, never a finding.
    const axfrNotAttempted = (result.details?.nameservers ?? [])
      .filter((n) => n.axfr?.attempted === false)
      .map((n) => ({ nameserver: n.nameserver, ...n.axfr }));
    // The checks a failed lookup left unmeasured, with their codes — a record, never a finding.
    const notMeasured = result.details?.notMeasured ?? [];
    const codeOf = (check) => notMeasured.find((e) => e.check === check)?.code;
    const said = (check, label, measured) => (codeOf(check) ? `${label} not measured (${codeOf(check)})` : measured);

    return [{
      port: 53,
      protocol: "udp",
      service: "dns-security",
      attachOnly: true,
      dnsSecurity: {
        // `action_required` wins; otherwise a run that could not measure every check is `incomplete`, never `hardened`.
        status: result.summary.actionable > 0 ? "action_required" : notMeasured.length > 0 ? "incomplete" : "hardened",
        severity: result.overallSeverity,
        actionable: result.summary.actionable,
        findings,
        ...(axfrNotAttempted.length ? { axfrNotAttempted } : {}),
        ...(notMeasured.length ? { notMeasured } : {}),
        ...(result.details?.axfrTested !== undefined ? { axfrTested: result.details.axfrTested } : {}),
      },
      info: [
        `${result.summary.actionable} actionable findings`,
        said("spf", "SPF", result.details.spfRecord ? "SPF present" : "SPF missing"),
        said("dmarc", "DMARC", result.details.dmarcRecord ? `DMARC p=${result.details.dmarcTags?.p || "?"}` : "DMARC missing"),
        said("dkim", "DKIM", result.details.dkimSelectors.length > 0
          ? `DKIM: ${result.details.dkimSelectors.length} selector(s)`
          : "DKIM: none found"),
        // G-75 (G4): the line reads the ROW — "DNSSEC active" only for dnssec_active — and names the zone it measured.
        said("dnssec", "DNSSEC", dnssecConcludeWords(result)),
      ].join(" | "),
      source: "dns-sec-auditor",
      authoritative: false,
    }];
  },

  authoritativePorts: new Set(),
};
