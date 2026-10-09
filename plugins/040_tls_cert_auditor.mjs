// plugins/040_tls_cert_auditor.mjs
// ─────────────────────────────────────────────────────────────────────────────
// NSAuditor AI – TLS Certificate & Cipher Auditor
// Tier: Community (no credentials needed — just a hostname)
// Protocol: tcp
// ZDE: Probes the target's public TLS handshake only. No cert data exfiltrated.
// ─────────────────────────────────────────────────────────────────────────────
//
// What this catches:
//   - Expired / expiring-soon certificates
//   - Self-signed certificates
//   - Hostname mismatch (CN/SAN vs target host)
//   - Weak signature algorithms (SHA-1, MD5, MD2)
//   - Weak / deprecated ciphers (RC4, 3DES, DES, NULL, EXPORT, ADH)
//   - Insecure protocol versions (SSLv3, TLSv1.0, TLSv1.1)
//   - Insufficient key sizes (RSA < 2048, EC < 256)
//   - Chain issues (expired intermediates, excessive depth)
//   - Missing OCSP stapling
//   - Certificate transparency (SCT) absence
//   - Wildcard certificate sprawl
//
// ─────────────────────────────────────────────────────────────────────────────

import tls from "node:tls";
import { isIP } from "node:net";
import { X509Certificate } from "node:crypto";

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
//    TLS_AUDIT_TIMEOUT_MS=8000
//    TLS_AUDIT_EXPIRY_WARN_DAYS=30
//    TLS_AUDIT_EXPIRY_CRITICAL_DAYS=7
//    TLS_AUDIT_MIN_RSA_BITS=2048
//    TLS_AUDIT_MIN_EC_BITS=256
//

function loadConfig(opts = {}) {
  return {
    timeoutMs:          parseInt(opts.timeoutMs          || process.env.TLS_AUDIT_TIMEOUT_MS          || "8000", 10),
    expiryWarnDays:     parseInt(opts.expiryWarnDays     || process.env.TLS_AUDIT_EXPIRY_WARN_DAYS    || "30", 10),
    expiryCriticalDays: parseInt(opts.expiryCriticalDays || process.env.TLS_AUDIT_EXPIRY_CRITICAL_DAYS || "7", 10),
    minRsaBits:         parseInt(opts.minRsaBits         || process.env.TLS_AUDIT_MIN_RSA_BITS        || "2048", 10),
    minEcBits:          parseInt(opts.minEcBits          || process.env.TLS_AUDIT_MIN_EC_BITS         || "256", 10),
  };
}

// ── Port-to-Service Mapping ──────────────────────────────────────────────────

const PORT_SERVICE_MAP = {
  443:  "https",
  465:  "smtps",
  587:  "smtp-submission",
  636:  "ldaps",
  853:  "dns-over-tls",
  993:  "imaps",
  995:  "pop3s",
  8443: "https-alt",
  8883: "mqtt-tls",
  9443: "https-alt",
};

function serviceForPort(port) {
  return PORT_SERVICE_MAP[port] || "tls";
}

// ── Weak Cipher & Protocol Sets ──────────────────────────────────────────────

const WEAK_CIPHER_FRAGMENTS = [
  "RC4", "3DES", "DES", "NULL", "EXPORT", "ADH", "AECDH",
  "anon", "SEED", "IDEA", "CAMELLIA128",
];

const DEPRECATED_PROTOCOLS = new Set(["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]);
const WEAK_SIG_ALGORITHMS  = /sha1WithRSA|md5WithRSA|md2WithRSA|sha1-with-rsa|dsaWithSHA1|ecdsa-with-SHA1/i;

// ⚠️ THE SIGNATURE ALGORITHM IS NOT ON getPeerCertificate() (1.3.0 build 5, Gate 3-A F-3b). Node's peer certificate
// carries subject, issuer, modulus, bits, raw … and no signature algorithm (measured on Node 24.12), so the leaf and
// chain checks below read "unknown" and could not fire from e96c8f9 (2026-04-08) on. It is in the DER: X509Certificate
// reads it on Node 24 (measured v24.12.0), and the getter does NOT EXIST on Node 22 (measured v22.23.3, the newest 22.x on
// 2026-10-09 — so on CE's engines floor, >=22) nor on Node 20 (v20.19.6). Where it cannot be read, the algorithm is NOT
// ASSESSED — never "unknown" read as a pass. The runtime sentence names the RUNNING version rather than a version list,
// so it stays true when the floor moves (it said "Node 20 does not" until the floor left Node 20).
export function signatureAlgorithmOf(peerCert) {
  if (!peerCert?.raw) return null;
  try {
    const alg = new X509Certificate(peerCert.raw).signatureAlgorithm;
    return typeof alg === "string" && alg ? alg : null;
  } catch {
    return null;
  }
}
// The reason is a claim, so it names the cause it measured: the runtime sentence only when the getter does not EXIST
// (checked when the strength is decided, not at load); any other null — no DER on the peer object, a parse failure —
// says the algorithm could not be read, so an operator is not sent to upgrade Node for a certificate it cannot parse.
export function signatureStrengthOf(sigAlg) {
  if (sigAlg) return "assessed";
  return "signatureAlgorithm" in X509Certificate.prototype
    ? "not assessed — the certificate's signature algorithm could not be read"
    : `not assessed — this Node runtime (${process.version}) does not report certificate signature algorithms; Node 24.12 does`;
}
// A certificate that issued itself: its own signature is verified by no client (an anchor, or a leaf that is its own).
const selfIssued = (c) => !!c?.issuerCertificate && c.issuerCertificate.fingerprint256 === c.fingerprint256;

// ── Hostname Validation ──────────────────────────────────────────────────────
// Checks CN and SANs against the target hostname, handling wildcards.

function validateHostname(cert, hostname) {
  if (isIP(hostname)) {
    // For IP connections, check IP SANs — as ADDRESSES, never as strings: Node prints an IPv6 SAN expanded
    // ("0:0:0:0:0:0:0:1") where the target may be written compressed ("::1").
    const target = canonicalAddress(hostname);
    return extractSANs(cert, "IP").some((san) => canonicalAddress(san) === target);
  }

  const names = getAllNames(cert);
  return names.some((name) => matchesHostname(name, hostname));
}

// The canonical text of an IP literal (IPv6 compressed, lower-case), or null for anything that is not one.
function canonicalAddress(addr) {
  const family = isIP(String(addr));
  if (!family) return null;
  try {
    return new URL(`http://${family === 6 ? `[${addr}]` : addr}/`).hostname;
  } catch {
    return null;
  }
}

function getAllNames(cert) {
  const names = [];

  // Subject CN
  if (cert.subject?.CN) {
    names.push(cert.subject.CN.toLowerCase());
  }

  // Subject Alternative Names
  const dnsSans = extractSANs(cert, "DNS");
  names.push(...dnsSans.map((s) => s.toLowerCase()));

  return [...new Set(names)];
}

function extractSANs(cert, type) {
  if (!cert.subjectaltname) return [];
  // 0.2.57: Node prints an IP SAN as "IP Address:<addr>" (measured — "DNS:a.example, IP Address:127.0.0.1"), so an
  // "IP:" filter alone never found one and every IP target read as a mismatch. Both spellings are read.
  const prefixes = type === "IP" ? ["IP Address:", "IP:"] : [`${type}:`];
  return cert.subjectaltname
    .split(",")
    .map((s) => s.trim())
    .flatMap((s) => {
      const p = prefixes.find((x) => s.startsWith(x));
      return p ? [s.slice(p.length)] : [];
    });
}

function matchesHostname(pattern, hostname) {
  pattern = pattern.toLowerCase();
  hostname = hostname.toLowerCase();

  if (pattern === hostname) return true;

  // Wildcard: *.example.com matches sub.example.com but NOT sub.sub.example.com
  if (pattern.startsWith("*.")) {
    const suffix = pattern.slice(2);
    const hostParts = hostname.split(".");
    if (hostParts.length < 2) return false;
    const hostSuffix = hostParts.slice(1).join(".");
    return hostSuffix === suffix;
  }

  return false;
}

// ── Chain Analysis ───────────────────────────────────────────────────────────

function analyzeChain(cert, now) {
  const chain = [];
  const issues = [];
  let current = cert;
  let depth = 0;
  const MAX_DEPTH = 10; // Guard against circular refs in getPeerCertificate(true)
  const seen = new Set();

  while (current && depth < MAX_DEPTH) {
    const fp = current.fingerprint256 || current.fingerprint || `depth-${depth}`;

    // Circular reference guard (node's getPeerCertificate can loop on self-signed)
    if (seen.has(fp)) break;
    seen.add(fp);

    const validTo = new Date(current.valid_to);
    const validFrom = new Date(current.valid_from);

    const entry = {
      depth,
      subject: current.subject?.CN || current.subject?.O || "unknown",
      issuer: current.issuer?.CN || current.issuer?.O || "unknown",
      validFrom: current.valid_from,
      validTo: current.valid_to,
      expired: now > validTo,
      notYetValid: now < validFrom,
      signatureAlgorithm: signatureAlgorithmOf(current) ?? "not reported",
    };

    chain.push(entry);

    if (depth > 0 && entry.expired) {
      issues.push({
        severity: SEVERITY.CRITICAL,
        check: "chain_intermediate_expired",
        detail: `Intermediate certificate expired: "${entry.subject}" (expired ${entry.validTo})`,
        depth,
      });
    }

    if (entry.notYetValid) {
      issues.push({
        severity: SEVERITY.HIGH,
        check: "chain_not_yet_valid",
        detail: `Certificate not yet valid: "${entry.subject}" (valid from ${entry.validFrom})`,
        depth,
      });
    }

    // Weak sig in chain — on an ISSUED certificate only. A self-signed terminal entry is the trust anchor, whose own
    // signature no client verifies (the architect seat's ruling, F-3b), so a SHA-1 root above SHA-256 certificates is
    // recorded and not graded.
    if (depth > 0 && !selfIssued(current) && WEAK_SIG_ALGORITHMS.test(entry.signatureAlgorithm)) {
      issues.push({
        severity: SEVERITY.MEDIUM,
        check: "chain_weak_signature",
        detail: `Intermediate "${entry.subject}" uses weak signature: ${entry.signatureAlgorithm}`,
        depth,
      });
    }

    current = current.issuerCertificate || null;
    depth++;
  }

  if (depth >= MAX_DEPTH) {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "chain_excessive_depth",
      detail: `Certificate chain depth exceeds ${MAX_DEPTH} — possible misconfiguration`,
    });
  }

  return { chain, issues, depth: chain.length };
}

// ── Key Strength Analysis ────────────────────────────────────────────────────

// ⚠️ THE TYPE COMES FROM THE FIELDS NODE ACTUALLY SETS (1.3.0 build 5, Gate 3-A F-3). Node's getPeerCertificate() gives
// `pubkey` as a raw Buffer with no `.type`; an RSA key carries `modulus` and `exponent`, an EC key a named curve
// (`asn1Curve` / `nistCurve`), and both carry `bits` (measured on Node 24.12). Until build 5 this read `cert.pubkey?.type`,
// so the type was always "unknown" and neither branch below could run on a real server — a 1024-bit RSA key raised
// nothing. A key of neither type (Ed25519 carries none of these fields) is NOT ASSESSED, said on certAudit, never silent.
export function analyzeKeyStrength(cert, config) {
  const issues = [];
  const keyType = cert.modulus ? "RSA" : (cert.asn1Curve || cert.nistCurve) ? "EC" : "unknown";
  const keyBits = Number.isFinite(cert.bits) && cert.bits > 0 ? cert.bits : null;

  const result = {
    type: keyType,
    bits: keyBits,
    strength: keyType === "unknown"
      ? "not assessed — the key is neither RSA (no modulus) nor EC (no named curve), so its size is not graded"
      : keyBits === null
        ? `not assessed — the ${keyType} key reported no size`
        : "assessed",
  };

  if (keyType === "RSA") {
    if (keyBits && keyBits < config.minRsaBits) {
      issues.push({
        severity: keyBits < 1024 ? SEVERITY.CRITICAL : SEVERITY.HIGH,
        check: "weak_rsa_key",
        detail: `RSA key is ${keyBits} bits (minimum recommended: ${config.minRsaBits})`,
      });
    }
  } else if (keyType === "EC") {
    if (keyBits && keyBits < config.minEcBits) {
      issues.push({
        severity: SEVERITY.HIGH,
        check: "weak_ec_key",
        detail: `EC key is ${keyBits} bits (minimum recommended: ${config.minEcBits})`,
      });
    }
  }

  return { keyInfo: result, issues };
}

// ── TLS Handshake Probe ──────────────────────────────────────────────────────

function probeTLS(host, port, config) {
  return new Promise((resolve) => {
    const startTime = Date.now();

    const options = {
      host,
      port,
      rejectUnauthorized: false,   // We WANT to see bad certs
      servername: isIP(host) ? undefined : host,  // SNI (only for hostnames, not IPs)
      timeout: config.timeoutMs,
    };

    const socket = tls.connect(options, () => {
      const latencyMs = Date.now() - startTime;
      const cert = socket.getPeerCertificate(true);  // true = full chain
      const cipher = socket.getCipher();
      const protocol = socket.getProtocol();
      const authorized = socket.authorized;
      const authError = socket.authorizationError || null;

      socket.end();

      if (!cert || !cert.subject) {
        resolve({
          up: true,
          handshake: true,
          noCert: true,
          latencyMs,
          protocol,
        });
        return;
      }

      resolve({
        up: true,
        handshake: true,
        noCert: false,
        cert,
        cipher,
        protocol,
        authorized,
        authError,
        latencyMs,
      });
    });

    socket.setTimeout(config.timeoutMs, () => {
      socket.destroy();
      resolve({ up: false, error: "TLS handshake timeout", latencyMs: Date.now() - startTime });
    });

    socket.on("error", (err) => {
      resolve({ up: false, error: err.code || err.message, latencyMs: Date.now() - startTime });
    });
  });
}

// ── Full Audit for One Port ──────────────────────────────────────────────────

async function auditPort(host, port, config) {
  const probe = await probeTLS(host, port, config);
  const now = new Date();
  const issues = [];

  if (!probe.up) {
    return {
      port,
      service: serviceForPort(port),
      up: false,
      error: probe.error,
      latencyMs: probe.latencyMs,
      severity: SEVERITY.INFO,
      issues: [],
    };
  }

  if (probe.noCert) {
    return {
      port,
      service: serviceForPort(port),
      up: true,
      error: "TLS handshake succeeded but no certificate presented",
      latencyMs: probe.latencyMs,
      severity: SEVERITY.HIGH,
      issues: [{
        severity: SEVERITY.HIGH,
        check: "no_certificate",
        detail: "Server completed TLS handshake without presenting a certificate",
      }],
    };
  }

  const cert = probe.cert;
  const cipher = probe.cipher;
  const protocol = probe.protocol;

  // ── Certificate Expiry ──────────────────────────────────────────────────
  const validTo = new Date(cert.valid_to);
  const validFrom = new Date(cert.valid_from);
  const daysToExpiry = Math.ceil((validTo - now) / 86_400_000);
  const expired = now > validTo;
  const notYetValid = now < validFrom;

  if (expired) {
    issues.push({
      severity: SEVERITY.CRITICAL,
      check: "cert_expired",
      detail: `Certificate expired ${Math.abs(daysToExpiry)} days ago (${cert.valid_to})`,
    });
  } else if (daysToExpiry <= config.expiryCriticalDays) {
    issues.push({
      severity: SEVERITY.CRITICAL,
      check: "cert_expiring_critical",
      detail: `Certificate expires in ${daysToExpiry} days (${cert.valid_to})`,
    });
  } else if (daysToExpiry <= config.expiryWarnDays) {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "cert_expiring_soon",
      detail: `Certificate expires in ${daysToExpiry} days (${cert.valid_to})`,
    });
  }

  if (notYetValid) {
    issues.push({
      severity: SEVERITY.HIGH,
      check: "cert_not_yet_valid",
      detail: `Certificate not valid until ${cert.valid_from}`,
    });
  }

  // ── Self-Signed Detection ──────────────────────────────────────────────
  const isSelfSigned =
    cert.subject?.CN === cert.issuer?.CN &&
    cert.subject?.O === cert.issuer?.O &&
    cert.fingerprint256 === cert.issuerCertificate?.fingerprint256;

  const selfSignedIssue = isSelfSigned
    ? { severity: SEVERITY.HIGH, check: "self_signed", detail: "Certificate is self-signed — not trusted by clients" }
    : null;
  if (selfSignedIssue) issues.push(selfSignedIssue);

  // ── Hostname Mismatch ──────────────────────────────────────────────────
  const hostnameValid = validateHostname(cert, host);
  if (!hostnameValid) {
    const certNames = getAllNames(cert).join(", ");
    // 0.2.57: graded by the target's form. Scanned by ADDRESS, a certificate that names DNS names only cannot match —
    // a true finding (a client connecting by address sees the mismatch), kept, but LOW: it is expected wherever the
    // service is reached by name. LOW, never INFO — the grading table drops `info`, which would hide it from every
    // reader. HIGH stays HIGH for a DNS-name target the certificate does not name, a certificate naming a DIFFERENT
    // address, and one naming no SAN at all.
    const dnsSans = extractSANs(cert, "DNS");
    const ipSans = extractSANs(cert, "IP");
    const byAddress = isIP(host) !== 0 && dnsSans.length > 0 && ipSans.length === 0;
    // A certificate with NO subjectAltName names no host a modern (RFC 6125) client checks — the CN is ignored — so
    // "does not match certificate names: <CN>" told the reader a usable name was present and merely differed. HIGH,
    // with that said (0.2.57, before this text had any prior identity in a delta).
    const noSan = dnsSans.length === 0 && ipSans.length === 0;
    issues.push(noSan
      ? {
        severity: SEVERITY.HIGH,
        check: "hostname_mismatch",
        detail: `Hostname "${host}": the certificate carries no subjectAltName — modern clients reject it for any name `
          + (cert.subject?.CN ? `(CN ${cert.subject.CN} is not checked)` : "(and it carries no CN either)"),
      }
      : byAddress
      ? {
        severity: SEVERITY.LOW,
        check: "hostname_mismatch",
        detail: `Hostname "${host}" does not match certificate names: ${certNames} — the certificate names DNS names only `
          + `(${dnsSans.join(", ")}); a client connecting by address sees a name mismatch, expected where the service is `
          + "reached by name",
      }
      : {
        severity: SEVERITY.HIGH,
        check: "hostname_mismatch",
        detail: `Hostname "${host}" does not match certificate names: ${certNames}`,
      });
  }

  // ── Wildcard Sprawl ────────────────────────────────────────────────────
  const allNames = getAllNames(cert);
  const wildcardNames = allNames.filter((n) => n.startsWith("*."));
  if (wildcardNames.length > 0) {
    issues.push({
      severity: SEVERITY.LOW,
      check: "wildcard_cert",
      detail: `Wildcard certificate in use: ${wildcardNames.join(", ")}`,
    });
  }

  // ── Signature Algorithm ────────────────────────────────────────────────
  // Read from the DER (signatureAlgorithmOf, above). A weak algorithm on a SELF-SIGNED leaf is not graded — the leaf is
  // its own anchor, so no client verifies that signature (option B, ruled) — and the self_signed finding says which
  // algorithm and why, so the skip is visible; the algorithm is recorded either way.
  const sigAlg = signatureAlgorithmOf(cert);
  const sigStrength = signatureStrengthOf(sigAlg);
  if (sigAlg && WEAK_SIG_ALGORITHMS.test(sigAlg)) {
    if (selfSignedIssue) {
      selfSignedIssue.detail += `; signed with ${sigAlg} — not graded on a self-signed certificate, whose signature no `
        + "client verifies (pin it by fingerprint)";
    } else {
      issues.push({
        severity: SEVERITY.HIGH,
        check: "weak_signature",
        detail: `Weak signature algorithm: ${sigAlg}`,
      });
    }
  }

  // ── Key Strength ───────────────────────────────────────────────────────
  const keyAnalysis = analyzeKeyStrength(cert, config);
  issues.push(...keyAnalysis.issues);

  // ── Negotiated Cipher ──────────────────────────────────────────────────
  const isWeakCipher = WEAK_CIPHER_FRAGMENTS.some((w) =>
    cipher.name.toUpperCase().includes(w.toUpperCase())
  );

  if (isWeakCipher) {
    issues.push({
      severity: SEVERITY.HIGH,
      check: "weak_cipher",
      detail: `Weak cipher negotiated: ${cipher.name}`,
    });
  }

  // Forward secrecy check. 0.2.57: TLS 1.3 by the PROTOCOL — every TLS 1.3 suite is ephemeral by construction, and
  // its name (TLS_AES_256_GCM_SHA384) carries neither ECDHE nor DHE, so the name test called every TLS 1.3 server
  // "no forward secrecy". Below TLS 1.3, the cipher name as before.
  const hasForwardSecrecy = protocol === "TLSv1.3" || /ECDHE|DHE/i.test(cipher.name);
  if (!hasForwardSecrecy) {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "no_forward_secrecy",
      detail: `Cipher ${cipher.name} does not provide forward secrecy (no ECDHE/DHE)`,
    });
  }

  // ── Protocol Version ───────────────────────────────────────────────────
  if (DEPRECATED_PROTOCOLS.has(protocol)) {
    issues.push({
      severity: protocol === "SSLv2" || protocol === "SSLv3" ? SEVERITY.CRITICAL : SEVERITY.HIGH,
      check: "deprecated_protocol",
      detail: `Insecure protocol negotiated: ${protocol}`,
    });
  }

  if (protocol !== "TLSv1.3") {
    issues.push({
      severity: SEVERITY.INFO,
      check: "not_tls13",
      detail: `Negotiated ${protocol} — TLSv1.3 preferred for best security`,
    });
  }

  // ── Chain Analysis ─────────────────────────────────────────────────────
  const chainAnalysis = analyzeChain(cert, now);
  issues.push(...chainAnalysis.issues);

  // ── Node.js authorization check (CA trust store validation) ────────────
  // 0.2.57: NOT on a name mismatch alone. With a chain the CA store VERIFIED and only the name wrong, Node reports
  // authorized=false with authorizationError ERR_TLS_CERT_ALTNAME_INVALID (measured: the same CA-signed certificate
  // reads authorized=true once its IP SAN matches the target), and this said the store distrusted a chain it trusted.
  // hostname_mismatch carries that fact. Keyed on the EXACT code: a chain that fails reports its own code, so an
  // untrusted chain with a wrong name keeps this finding beside the mismatch.
  //
  // 1.3.0 build 5 (the architect seat's ruling): Node reports UNSPECIFIED for a verify error outside its named table —
  // measured for a 1024-bit leaf key and for a SHA-1 signature under a CA the store DOES hold, both refused by the
  // verifier's policy. "Not trusted by system CA store" would name a cause that is false there, so UNSPECIFIED states the
  // fact and no cause; where this certificate carries a graded weak key or signature, it points at that grade (a pointer,
  // not a causal claim — the refusal's cause is not measured here). Named codes keep their wording.
  if (!probe.authorized && !isSelfSigned && probe.authError !== "ERR_TLS_CERT_ALTNAME_INVALID") {
    const weakGrade = issues.some((i) => ["weak_rsa_key", "weak_ec_key", "weak_signature", "chain_weak_signature"].includes(i.check));
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "ca_not_trusted",
      detail: probe.authError === "UNSPECIFIED"
        ? "Certificate chain refused by this runtime's verifier — Node reports no named reason (UNSPECIFIED)"
          + (weakGrade ? "; the graded weak key / signature on this certificate is the actionable finding" : "")
        : `Certificate not trusted by system CA store: ${probe.authError || "unknown reason"}`,
    });
  }

  // ── Compute Overall Severity ───────────────────────────────────────────
  let severity = SEVERITY.PASS;
  for (const issue of issues) {
    if (SEVERITY_RANK[issue.severity] > SEVERITY_RANK[severity]) {
      severity = issue.severity;
    }
  }

  return {
    port,
    service: serviceForPort(port),
    up: true,
    latencyMs: probe.latencyMs,
    severity,
    certificate: {
      subject: cert.subject,
      issuer: cert.issuer,
      validFrom: cert.valid_from,
      validTo: cert.valid_to,
      daysToExpiry,
      expired,
      notYetValid,
      selfSigned: isSelfSigned,
      hostnameValid,
      names: allNames,
      signatureAlgorithm: sigAlg ?? "not reported",
      signatureStrength: sigStrength,
      keyType: keyAnalysis.keyInfo.type,
      keyBits: keyAnalysis.keyInfo.bits,
      keyStrength: keyAnalysis.keyInfo.strength,
      fingerprint256: cert.fingerprint256,
      serialNumber: cert.serialNumber,
    },
    chain: {
      depth: chainAnalysis.depth,
      entries: chainAnalysis.chain,
    },
    negotiation: {
      protocol,
      cipher: cipher.name,
      cipherVersion: cipher.version,
      forwardSecrecy: hasForwardSecrecy,
      isWeakCipher,
    },
    authorized: probe.authorized,
    authError: probe.authError,
    issues,
  };
}

// ── A certificate audit that did not happen is SAID, where the reader looks ────
// Through CE 0.2.55 a failed handshake reached only the INFO `tls-not-responding` service row,
// which the report loader never shapes. EE 1.1.0 build 6's Gate-2 run had 443 OPEN per the port
// scanner, and 040's handshake there was RESET (`ECONNRESET`): `totalIssues 0`, `overallSeverity:
// "pass"`. The executive report said nothing about a certificate audit that never happened.
//
// ⚠️ KEYED ON WHAT THE PORT SCANNER SAW, NOT ON THE ERROR. The test estate's router answers
// ENETDOWN on 993/995 in every run since 0.34.0, and the port scanner reads the same, so those ports
// were never open. A rule keyed on "any error but ECONNREFUSED" would have put a gap on every scan
// (measured over the evidence tree before this was written).
//   · WITH port-scanner evidence (`context.tcpOpen` is a Set AND 003 ran): a failed port is a gap iff
//     003 saw it open — with ANY error, a refusal included, since it was open moments earlier.
//   · WITHOUT it (a direct call, or 003 not measured): every failure except ECONNREFUSED is a gap,
//     restricted to the NAMED port when the call names one. It is stated as `openness: 'unknown'`.
// The gap is a FINDING in `result.findings`, the container the loader reads, flagged
// `details.evidenceGap`: it is shown AS a gap and excluded from the finding count. The INFO row stays.
export function tlsCoverageGap(failedPorts, context, namedPort) {
  const failed = Array.isArray(failedPorts) ? failedPorts : [];
  const tcpOpen = context?.tcpOpen instanceof Set ? context.tcpOpen : null;
  const scannerRan = context?.pluginRunStatus instanceof Map && context.pluginRunStatus.get("003") === "ran";
  const evidence = tcpOpen !== null && scannerRan;
  const named = Number(namedPort) > 0 ? Number(namedPort) : null;
  const gaps = evidence
    ? failed.filter((f) => tcpOpen.has(Number(f.port)))
    : failed.filter((f) => f.error !== "ECONNREFUSED" && (named === null || Number(f.port) === named));
  if (gaps.length === 0) return null;
  const list = gaps.map((f) => `${f.port} (${f.error})`).join(", ");
  return {
    severity: SEVERITY.INFO,
    check: "tls_audit_incomplete",
    title: `[COVERAGE GAP] TLS certificate audit could not complete on ${list}`,
    detail: evidence
      ? `The port scanner saw ${gaps.length === 1 ? "this port" : "these ports"} open, and the TLS handshake failed: ` +
        "the certificate, chain, cipher and protocol checks did not run there. This is not a pass."
      : "The TLS handshake failed, and this run holds no port-scanner evidence of whether the port was open: " +
        "the certificate, chain, cipher and protocol checks did not run there. This is not a pass.",
    port: gaps.length === 1 ? Number(gaps[0].port) : null,
    details: {
      evidenceGap: true,
      openness: evidence ? "open-per-port-scanner" : "unknown",
      failedPorts: gaps,
    },
  };
}

// ── Plugin Export ─────────────────────────────────────────────────────────────

export default {
  id: "040",
  name: "TLS Certificate & Cipher Auditor",
  description:
    "Audits TLS certificates for expiry, chain integrity, self-signed status, " +
    "hostname mismatch, weak ciphers, deprecated protocols, key strength, and " +
    "forward secrecy. Scans all common TLS ports.",
  priority: 450,
  tier: "community",
  protocols: ["tcp"],
  ports: [443, 465, 587, 636, 853, 993, 995, 8443, 8883, 9443],
  // single invocation: run() iterates this.ports internally so failed ports
  // can be rolled up into one INFO instead of N per-port empty placeholders.
  runStrategy: "single",

  requirements: {
    host: "up",
  },

  // ── Pre-flight ──────────────────────────────────────────────────────────
  preflight() {
    return { ready: true };
  },

  // ── Main Execution ──────────────────────────────────────────────────────
  async run(host, port, opts = {}) {
    const config = loadConfig(opts);
    const startTime = Date.now();

    // Determine which ports to scan
    // If a specific port was passed, use it. Otherwise scan all known TLS ports.
    const portsToScan = port
      ? [port]
      : this.ports;

    const results = [];

    for (const targetPort of portsToScan) {
      const result = await auditPort(host, targetPort, config);
      results.push(result);
    }

    // Filter to only ports that responded
    const activeResults = results.filter((r) => r.up);
    const failedPorts = results.filter((r) => !r.up).map((r) => ({
      port: r.port,
      error: r.error,
    }));

    // Overall severity across all ports
    let overallSeverity = SEVERITY.PASS;
    for (const r of activeResults) {
      if (SEVERITY_RANK[r.severity] > SEVERITY_RANK[overallSeverity]) {
        overallSeverity = r.severity;
      }
    }

    // Summary
    const allIssues = activeResults.flatMap((r) => r.issues);
    const summary = {
      portsScanned: portsToScan.length,
      portsActive: activeResults.length,
      totalIssues: allIssues.length,
      critical: allIssues.filter((i) => i.severity === SEVERITY.CRITICAL).length,
      high:     allIssues.filter((i) => i.severity === SEVERITY.HIGH).length,
      medium:   allIssues.filter((i) => i.severity === SEVERITY.MEDIUM).length,
      low:      allIssues.filter((i) => i.severity === SEVERITY.LOW).length,
      info:     allIssues.filter((i) => i.severity === SEVERITY.INFO).length,
    };

    const coverageGap = tlsCoverageGap(failedPorts, opts.context, port);

    return {
      up: activeResults.length > 0,
      audit_type: "tls_certificate",
      host,
      overallSeverity,
      duration_ms: Date.now() - startTime,
      summary,
      portResults: activeResults,
      failedPorts,
      ...(coverageGap ? { findings: [coverageGap] } : {}),
    };
  },

  // ── Conclude ────────────────────────────────────────────────────────────
  conclude({ result, host }) {
    const portResults = Array.isArray(result?.portResults) ? result.portResults : [];
    const failedPorts = Array.isArray(result?.failedPorts) ? result.failedPorts : [];

    if (portResults.length === 0 && failedPorts.length === 0) {
      return [{
        protocol: "tcp",
        service: "tls",
        status: "no_tls_detected",
        severity: SEVERITY.INFO,
        info: "No TLS services found on scanned ports",
        source: "tls-cert-auditor",
      }];
    }

    const items = [];

    for (const pr of portResults) {
      // Compute status label
      let status;
      if (pr.certificate.expired) {
        status = "expired";
      } else if (pr.certificate.daysToExpiry <= 7) {
        status = "expiring-critical";
      } else if (pr.certificate.daysToExpiry <= 30) {
        status = "expiring-soon";
      } else {
        status = "valid";
      }

      // Actionable issues (skip PASS and INFO), each with its OWN severity and check — 1.3.0 (s1): the shared
      // service-flag table grades one finding per issue, and a detail string alone left only the port's roll-up.
      const actionableIssues = pr.issues
        .filter((i) => i.severity !== SEVERITY.PASS && i.severity !== SEVERITY.INFO)
        .map((i) => ({ severity: i.severity, check: i.check, detail: i.detail }));
      // The roll-up is DERIVED from the issues carried here, never copied from the port result: a second copy of a datum
      // is a copy that can disagree. Null when nothing is actionable.
      const rollUp = [SEVERITY.CRITICAL, SEVERITY.HIGH, SEVERITY.MEDIUM, SEVERITY.LOW]
        .find((sev) => actionableIssues.some((i) => i.severity === sev)) ?? null;

      // 1.3.0: the audit travels under `certAudit`, never in identity. This record wrote program "TLS" and the
      // NEGOTIATED protocol as the service version, and once the concluder reached it, that version would have
      // filled the blank on the TLS scanner's authoritative record.
      items.push({
        port: pr.port,
        protocol: "tcp",
        service: pr.service,
        status: "open",
        info: [
          status,
          `${pr.certificate.daysToExpiry}d remaining`,
          pr.negotiation.cipher,
          pr.negotiation.forwardSecrecy ? "FS" : "no-FS",
          pr.certificate.selfSigned ? "self-signed" : null,
          pr.certificate.hostnameValid ? null : "hostname-mismatch",
        ].filter(Boolean).join(" | "),
        certAudit: {
          severity: rollUp,
          certStatus: status,
          negotiatedProtocol: pr.negotiation.protocol,
          issues: actionableIssues,
          details: {
            subject: pr.certificate.subject,
            issuer: pr.certificate.issuer,
            names: pr.certificate.names,
            validFrom: pr.certificate.validFrom,
            validTo: pr.certificate.validTo,
            signatureAlgorithm: pr.certificate.signatureAlgorithm,
            signatureStrength: pr.certificate.signatureStrength,
            keyType: pr.certificate.keyType,
            keyBits: pr.certificate.keyBits,
            keyStrength: pr.certificate.keyStrength,
            chainDepth: pr.chain.depth,
            authorized: pr.authorized,
          },
        },
        // ZDE: fingerprints and serial numbers stay in-process.
        // Conclude emits only classifications and metadata.
        source: "tls-cert-auditor",
        authoritative: false,  // Defer to built-in TLS scanner for port authority
      });
    }

    if (failedPorts.length > 0) {
      const probedTotal = portResults.length + failedPorts.length;
      items.push({
        port: 0,
        protocol: "tcp",
        service: "tls",
        status: "tls-not-responding",
        severity: SEVERITY.INFO,
        info: `${failedPorts.length}/${probedTotal} TLS ports did not respond (${failedPorts.map((f) => `${f.port}: ${f.error}`).join(", ")})`,
        issues: [],
        details: {
          failedPorts,
          activePorts: portResults.map((pr) => pr.port),
        },
        source: "tls-cert-auditor",
        authoritative: false,
      });
    }

    return items;
  },

  // Empty = don't steal authority from built-in scanner
  authoritativePorts: new Set(),
};
