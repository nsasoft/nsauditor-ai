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
import { classifyAddress, allowAllHosts } from "../utils/net_validation.mjs";

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
//  Optional .env:
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

// The checks in the order the result lists them, and their names in the reason a not-measured run carries.
const CHECK_LABELS = [
  ["cname", "CNAME"], ["spf", "SPF"], ["dmarc", "DMARC"], ["dkim", "DKIM"], ["ns", "NS"],
  ["dnssec", "DNSSEC"], ["mx", "MX"], ["caa", "CAA"], ["wildcard", "wildcard"],
];
const andList = (xs) => (xs.length <= 1 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`);

// The reason a partly measured run reports: which checks were not measured and with which code, and which were. A
// reader that only prints `reason` (a compliance gap row, for one) then still says what the result holds.
function notMeasuredReason(notMeasured) {
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
  const measured = CHECK_LABELS.filter(([check]) => !codeOf.has(check)).map(([, label]) => label);
  const notCount = codeOf.size === 1 ? "that check is" : `those ${codeOf.size} checks are`;
  const tail = measured.length === 0 ? "no check was measured"
    : `${andList(measured)} ${measured.length === 1 ? "was measured and its findings are" : "were measured and their findings are"} in the result`;
  return `resolver failure on ${failed}: ${notCount} not measured; ${tail}`;
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
  let firstFailure = null;   // the first selector lookup that failed to measure, if no selector is found

  for (const selector of selectors) {
    const name = `${selector}._domainkey.${host}`;
    const { records, error } = await resolveTxtFlat(name);
    if (failedToMeasure(error) && !firstFailure) firstFailure = { name, code: error };
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

  // "None found" is a measurement only when every selector lookup answered; one that failed might have been the one.
  if (found.length === 0 && firstFailure) {
    notMeasured.push({ check: "dkim", rrtype: "TXT", name: firstFailure.name, code: firstFailure.code });
  } else if (found.length === 0) {
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

      // Private IP check
      for (const ip of ips) {
        if (isPrivateIP(ip)) {
          issues.push({
            severity: SEVERITY.HIGH,
            check: "ns_private_ip",
            detail: `Nameserver ${nsStr} resolves to private IP ${ip} — unreachable from public internet`,
          });
        }
      }
    } catch (err) {
      const code = err?.code || err?.message;
      // NODATA on A says the name exists with no IPv4 address — it may answer over IPv6. NXDOMAIN answers for every type.
      const v6 = code === "ENODATA" ? await safeResolve(dns.resolve6, nsStr) : null;
      if (v6 && !v6.error) {
        entry.resolves = true;
        entry.ips6 = v6;
      } else if (isAbsence(code) && (!v6 || isAbsence(v6.error))) {
        issues.push({
          severity: SEVERITY.HIGH,
          check: "ns_lame_delegation",
          detail: `Nameserver ${nsStr} does not resolve — lame delegation`,
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

function isPrivateIP(ip) {
  return (
    ip.startsWith("10.") ||
    ip.startsWith("172.16.") || ip.startsWith("172.17.") || ip.startsWith("172.18.") ||
    ip.startsWith("172.19.") || ip.startsWith("172.20.") || ip.startsWith("172.21.") ||
    ip.startsWith("172.22.") || ip.startsWith("172.23.") || ip.startsWith("172.24.") ||
    ip.startsWith("172.25.") || ip.startsWith("172.26.") || ip.startsWith("172.27.") ||
    ip.startsWith("172.28.") || ip.startsWith("172.29.") || ip.startsWith("172.30.") ||
    ip.startsWith("172.31.") ||
    ip.startsWith("192.168.") ||
    ip === "127.0.0.1" ||
    ip.startsWith("169.254.")
  );
}

// ── Module 7: DNSSEC Probe ───────────────────────────────────────────────────
// Node.js dns module doesn't natively support DNSSEC validation.
// We check for DNSKEY and DS records as indicators of DNSSEC deployment.

async function probeDNSSEC(host, notMeasured) {
  const issues = [];

  // Primary: direct DNSKEY and DS queries
  const [dnskeyResult, dsResult] = await Promise.all([
    safeResolve(dns.resolve, host, "DNSKEY"),
    safeResolve(dns.resolve, host, "DS"),
  ]);

  let hasDNSKEY = !dnskeyResult?.error && Array.isArray(dnskeyResult) && dnskeyResult.length > 0;
  let hasDS = !dsResult?.error && Array.isArray(dsResult) && dsResult.length > 0;

  // Fallback: resolveAny() can surface DNSKEY/DS on resolvers that support it.
  // Some resolvers (e.g. Cloudflare) REFUSE ANY queries, so this is best-effort — and a refused ANY measures nothing
  // either way: only the primary DNSKEY and DS queries decide whether an absence was measured.
  if (!hasDNSKEY && !hasDS) {
    const anyResult = await safeResolve(dns.resolveAny, host);
    if (!anyResult?.error && Array.isArray(anyResult)) {
      if (anyResult.some((r) => r.type === "DNSKEY")) hasDNSKEY = true;
      if (anyResult.some((r) => r.type === "DS")) hasDS = true;
    }
  }

  // A record type not found whose query failed to measure is unknown, not absent.
  const dnskeyUnknown = !hasDNSKEY && failedToMeasure(dnskeyResult?.error);
  const dsUnknown = !hasDS && failedToMeasure(dsResult?.error);
  const unknown = (rrtype, code) => {
    notMeasured.push({ check: "dnssec", rrtype, name: host, code });
    return { hasDNSKEY: hasDNSKEY || (dnskeyUnknown ? null : false), hasDS: hasDS || (dsUnknown ? null : false), issues };
  };
  if (!hasDNSKEY && !hasDS && (dnskeyUnknown || dsUnknown)) {
    return dnskeyUnknown ? unknown("DNSKEY", dnskeyResult.error) : unknown("DS", dsResult.error);
  }
  if (hasDNSKEY && dsUnknown) return unknown("DS", dsResult.error);

  if (!hasDNSKEY && !hasDS) {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "no_dnssec",
      detail: "No DNSSEC deployment detected (no DNSKEY or DS records) — DNS responses can be spoofed",
    });
  } else if (hasDNSKEY && !hasDS) {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "dnssec_partial",
      detail: "DNSKEY present but no DS record in parent — DNSSEC chain of trust is broken",
    });
  } else if (hasDNSKEY && hasDS) {
    issues.push({
      severity: SEVERITY.PASS,
      check: "dnssec_active",
      detail: "DNSSEC is deployed (DNSKEY + DS records present)",
    });
  }

  return { hasDNSKEY, hasDS, issues };
}

// ── Module 8: Zone Transfer Check (AXFR) ────────────────────────────────────
// An open zone transfer is a critical finding — it dumps the entire zone.

async function checkZoneTransfer(host, nameservers, config) {
  const issues = [];

  if (!config.checkAxfr || nameservers.length === 0) {
    return { issues };
  }

  for (const ns of nameservers) {
    if (!ns.resolves || ns.ips.length === 0) continue;

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
    const vulnerable = await attemptAXFR(host, ip, config.timeoutMs);

    if (vulnerable) {
      issues.push({
        severity: SEVERITY.CRITICAL,
        check: "axfr_open",
        detail: `Zone transfer (AXFR) allowed on ${ns.nameserver} (${ip}) — entire zone is exposed`,
        nameserver: ns.nameserver,
      });
    }
  }

  return { issues };
}

function attemptAXFR(domain, nsIP, timeoutMs) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      socket.destroy();
      resolve(false);
    }, timeoutMs);

    const socket = net.createConnection({ host: nsIP, port: 53 }, () => {
      // Build a minimal AXFR query
      const query = buildAXFRQuery(domain);
      // TCP DNS: 2-byte length prefix
      const lenBuf = Buffer.alloc(2);
      lenBuf.writeUInt16BE(query.length);
      socket.write(Buffer.concat([lenBuf, query]));
    });

    let received = Buffer.alloc(0);

    socket.on("data", (data) => {
      received = Buffer.concat([received, data]);
      // If we got more than just a header + error, AXFR probably worked
      if (received.length > 14) {
        // Check RCODE in response header (byte 3, lower 4 bits)
        // Skip the 2-byte TCP length prefix
        if (received.length > 5) {
          const flags = received.readUInt8(5);  // 2 (len prefix) + 3 (flags byte 2)
          const rcode = flags & 0x0f;
          // RCODE 0 = NOERROR, and if we got answer records, AXFR is open
          if (rcode === 0 && received.length > 50) {
            clearTimeout(timer);
            socket.destroy();
            resolve(true);
            return;
          }
        }
        // REFUSED or SERVFAIL = properly denied
        clearTimeout(timer);
        socket.destroy();
        resolve(false);
      }
    });

    socket.on("error", () => {
      clearTimeout(timer);
      resolve(false);
    });

    socket.on("close", () => {
      clearTimeout(timer);
      resolve(false);
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
      probeDNSSEC(host, notMeasured),
      analyzeMX(records, host, notMeasured),
      Promise.resolve(analyzeCAA(records, host, notMeasured)),
      checkWildcard(host, notMeasured),
    ]);
    const checkOrder = new Map(CHECK_LABELS.map(([check], i) => [check, i]));
    notMeasured.sort((x, y) => checkOrder.get(x.check) - checkOrder.get(y.check));

    // 3. Zone transfer check (depends on NS results)
    const axfr = await checkZoneTransfer(host, nsCheck.nameservers, config);

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
      ...(notMeasured.length > 0 ? { reason: notMeasuredReason(notMeasured) } : {}),
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
        dnssec: { hasDNSKEY: dnssec.hasDNSKEY, hasDS: dnssec.hasDS },
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
      .map((f) => ({ severity: f.severity, category: f.category, check: f.check, detail: f.detail }));
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
      },
      info: [
        `${result.summary.actionable} actionable findings`,
        said("spf", "SPF", result.details.spfRecord ? "SPF present" : "SPF missing"),
        said("dmarc", "DMARC", result.details.dmarcRecord ? `DMARC p=${result.details.dmarcTags?.p || "?"}` : "DMARC missing"),
        said("dkim", "DKIM", result.details.dkimSelectors.length > 0
          ? `DKIM: ${result.details.dkimSelectors.length} selector(s)`
          : "DKIM: none found"),
        said("dnssec", "DNSSEC", result.details.dnssec.hasDNSKEY ? "DNSSEC active" : "no DNSSEC"),
      ].join(" | "),
      source: "dns-sec-auditor",
      authoritative: false,
    }];
  },

  authoritativePorts: new Set(),
};
