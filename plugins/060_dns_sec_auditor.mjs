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
//    DNS_AUDIT_AXFR_CHECK=true
//

function loadConfig(opts = {}) {
  const defaultSelectors = "google,default,mail,selector1,selector2,s1,s2,k1,k2,k3,dkim,mandrill,mailjet,ses,zoho,protonmail,mimecast,mailchimp";
  return {
    timeoutMs: parseInt(opts.timeoutMs || process.env.DNS_AUDIT_TIMEOUT_MS || "5000", 10),
    dkimSelectors: (opts.dkimSelectors || process.env.DNS_AUDIT_DKIM_SELECTORS || defaultSelectors)
      .split(",").map((s) => s.trim()).filter(Boolean),
    checkAxfr: (opts.checkAxfr || process.env.DNS_AUDIT_AXFR_CHECK || "true") === "true",
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
  };
}

// ── Module 2: Dangling CNAME Detection ───────────────────────────────────────

async function checkDanglingCname(records) {
  const issues = [];

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

    const a4Failed = a4?.error && (a4.error === "ENOTFOUND" || a4.error === "ENODATA");
    const a6Failed = a6?.error && (a6.error === "ENOTFOUND" || a6.error === "ENODATA");

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

function analyzeSPF(txtRecords) {
  const issues = [];
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

async function analyzeDMARC(host) {
  const issues = [];
  const { records, error } = await resolveTxtFlat(`_dmarc.${host}`);

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

async function discoverDKIM(host, selectors) {
  const issues = [];
  const found = [];

  for (const selector of selectors) {
    const { records, error } = await resolveTxtFlat(`${selector}._domainkey.${host}`);
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

  if (found.length === 0) {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "dkim_none_found",
      detail: `No DKIM selectors found among ${selectors.length} common selectors — DKIM may use custom selectors`,
    });
  }

  return { selectors: found, issues };
}

// ── Module 6: NS Delegation Hygiene ──────────────────────────────────────────

async function analyzeNS(records) {
  const issues = [];
  const ns = records.NS;

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
    } catch {
      issues.push({
        severity: SEVERITY.HIGH,
        check: "ns_lame_delegation",
        detail: `Nameserver ${nsStr} does not resolve — lame delegation`,
      });
    }

    nsDetails.push(entry);
  }

  // Check NS diversity (all on same /24?)
  const uniqueC = new Set(
    nsDetails.flatMap((n) => n.ips.map((ip) => ip.split(".").slice(0, 3).join(".")))
  );
  if (uniqueC.size === 1 && nsDetails.length > 1) {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "ns_same_subnet",
      detail: "All nameservers are in the same /24 subnet — no network diversity",
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

async function probeDNSSEC(host) {
  const issues = [];

  // Primary: direct DNSKEY and DS queries
  const [dnskeyResult, dsResult] = await Promise.all([
    safeResolve(dns.resolve, host, "DNSKEY"),
    safeResolve(dns.resolve, host, "DS"),
  ]);

  let hasDNSKEY = !dnskeyResult?.error && Array.isArray(dnskeyResult) && dnskeyResult.length > 0;
  let hasDS = !dsResult?.error && Array.isArray(dsResult) && dsResult.length > 0;

  // Fallback: resolveAny() can surface DNSKEY/DS on resolvers that support it.
  // Some resolvers (e.g. Cloudflare) REFUSE ANY queries, so this is best-effort.
  if (!hasDNSKEY && !hasDS) {
    const anyResult = await safeResolve(dns.resolveAny, host);
    if (!anyResult?.error && Array.isArray(anyResult)) {
      if (anyResult.some((r) => r.type === "DNSKEY")) hasDNSKEY = true;
      if (anyResult.some((r) => r.type === "DS")) hasDS = true;
    }
  }

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

async function analyzeMX(records, host) {
  const issues = [];
  const mx = records.MX;

  if (!mx || mx.length === 0) {
    // Check for null MX (RFC 7505)
    const { records: txtRecs } = await resolveTxtFlat(host);
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
    if (!cnameCheck?.error) {
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

function analyzeCAA(records) {
  const issues = [];
  const caa = records.CAA;

  if (!caa || caa.length === 0) {
    issues.push({
      severity: SEVERITY.LOW,
      check: "no_caa",
      detail: "No CAA records — any CA can issue certificates for this domain",
    });
    return { records: [], issues };
  }

  const hasIssue = caa.some((r) => r.critical !== undefined);
  const issueTags = caa.filter((r) => r.tag === "issue" || r.tag === "issuewild");

  if (issueTags.length > 0) {
    issues.push({
      severity: SEVERITY.PASS,
      check: "caa_present",
      detail: `CAA records restrict certificate issuance to: ${issueTags.map((r) => r.value).join(", ")}`,
    });
  }

  // Check for iodef (incident reporting)
  const iodef = caa.find((r) => r.tag === "iodef");
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

async function checkWildcard(host) {
  const issues = [];
  const randomSub = `nsauditor-wildcard-probe-${Date.now()}.${host}`;

  const result = await safeResolve(dns.resolve4, randomSub);
  if (!result?.error) {
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
    const config = loadConfig(opts);
    const startTime = Date.now();

    // 1. Collect all DNS records
    const records = await collectRecords(host);

    // 2. Run all analysis modules
    const [cname, spf, dmarc, dkim, nsCheck, dnssec, mx, caa, wildcard] = await Promise.all([
      checkDanglingCname(records),
      Promise.resolve(analyzeSPF(records.TXT)),
      analyzeDMARC(host),
      discoverDKIM(host, config.dkimSelectors),
      analyzeNS(records),
      probeDNSSEC(host),
      analyzeMX(records, host),
      Promise.resolve(analyzeCAA(records)),
      checkWildcard(host),
    ]);

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
    };

    return {
      up: true,
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
        hasSOA: !!records.SOA,
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
      },
    };
  },

  // ── Conclude ────────────────────────────────────────────────────────────
  conclude({ result, host }) {
    if (!result.findings) return [];

    const items = [];

    // Summary item
    items.push({
      port: 53,
      protocol: "udp",
      service: "dns-security",
      program: "DNS-Audit",
      version: "v2",
      status: result.summary.actionable > 0 ? "action_required" : "hardened",
      severity: result.overallSeverity,
      info: [
        `${result.summary.actionable} actionable findings`,
        result.details.spfRecord ? "SPF present" : "SPF missing",
        result.details.dmarcRecord ? `DMARC p=${result.details.dmarcTags?.p || "?"}` : "DMARC missing",
        result.details.dkimSelectors.length > 0
          ? `DKIM: ${result.details.dkimSelectors.length} selector(s)`
          : "DKIM: none found",
        result.details.dnssec.hasDNSKEY ? "DNSSEC active" : "no DNSSEC",
      ].join(" | "),
      source: "dns-sec-auditor",
      authoritative: false,
    });

    // Individual actionable findings
    const allFindings = Object.entries(result.findings).flatMap(
      ([category, issues]) => issues.map((i) => ({ ...i, category }))
    );

    for (const f of allFindings) {
      if (f.severity === SEVERITY.PASS || f.severity === SEVERITY.INFO) continue;

      items.push({
        protocol: "dns",
        service: "dns-security",
        severity: f.severity,
        status: "action_required",
        category: f.category,
        check: f.check,
        info: f.detail,
        source: "dns-sec-auditor",
      });
    }

    return items;
  },

  authoritativePorts: new Set(),
};
