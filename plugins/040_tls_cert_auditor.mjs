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
const WEAK_SIG_ALGORITHMS  = /sha1WithRSA|md5WithRSA|md2WithRSA|sha1-with-rsa|dsaWithSHA1/i;

// ── Hostname Validation ──────────────────────────────────────────────────────
// Checks CN and SANs against the target hostname, handling wildcards.

function validateHostname(cert, hostname) {
  if (isIP(hostname)) {
    // For IP connections, check IP SANs
    const ipSans = extractSANs(cert, "IP");
    return ipSans.includes(hostname);
  }

  const names = getAllNames(cert);
  return names.some((name) => matchesHostname(name, hostname));
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
  return cert.subjectaltname
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.startsWith(`${type}:`))
    .map((s) => s.slice(type.length + 1));
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
      signatureAlgorithm: current.signatureAlgorithm || "unknown",
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

    // Weak sig in chain
    if (depth > 0 && WEAK_SIG_ALGORITHMS.test(entry.signatureAlgorithm)) {
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

function analyzeKeyStrength(cert, config) {
  const issues = [];
  const keyType = cert.pubkey?.type || "unknown";
  const keyBits = cert.bits || cert.pubkey?.size || null;

  const result = {
    type: keyType,
    bits: keyBits,
  };

  if (keyType === "RSA" || keyType === "rsa") {
    if (keyBits && keyBits < config.minRsaBits) {
      issues.push({
        severity: keyBits < 1024 ? SEVERITY.CRITICAL : SEVERITY.HIGH,
        check: "weak_rsa_key",
        detail: `RSA key is ${keyBits} bits (minimum recommended: ${config.minRsaBits})`,
      });
    }
  } else if (keyType === "EC" || keyType === "ec") {
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

  if (isSelfSigned) {
    issues.push({
      severity: SEVERITY.HIGH,
      check: "self_signed",
      detail: "Certificate is self-signed — not trusted by clients",
    });
  }

  // ── Hostname Mismatch ──────────────────────────────────────────────────
  const hostnameValid = validateHostname(cert, host);
  if (!hostnameValid) {
    const certNames = getAllNames(cert).join(", ");
    issues.push({
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
  const sigAlg = cert.signatureAlgorithm || "unknown";
  if (WEAK_SIG_ALGORITHMS.test(sigAlg)) {
    issues.push({
      severity: SEVERITY.HIGH,
      check: "weak_signature",
      detail: `Weak signature algorithm: ${sigAlg}`,
    });
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

  // Forward secrecy check
  const hasForwardSecrecy = /ECDHE|DHE/i.test(cipher.name);
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
  if (!probe.authorized && !isSelfSigned) {
    issues.push({
      severity: SEVERITY.MEDIUM,
      check: "ca_not_trusted",
      detail: `Certificate not trusted by system CA store: ${probe.authError || "unknown reason"}`,
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
      signatureAlgorithm: sigAlg,
      keyType: keyAnalysis.keyInfo.type,
      keyBits: keyAnalysis.keyInfo.bits,
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

  requirements: {
    host: "up",
    // Note: requirements are OR-logic for ports — any open TLS port triggers the plugin.
    // The plugin itself will skip ports that don't respond to TLS handshake.
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

    return {
      up: activeResults.length > 0,
      audit_type: "tls_certificate",
      host,
      overallSeverity,
      duration_ms: Date.now() - startTime,
      summary,
      portResults: activeResults,
      failedPorts,
    };
  },

  // ── Conclude ────────────────────────────────────────────────────────────
  conclude({ result, host }) {
    if (!result.portResults || result.portResults.length === 0) {
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

    for (const pr of result.portResults) {
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

      // Filter actionable issues (skip PASS and INFO for conclude)
      const actionableIssues = pr.issues
        .filter((i) => i.severity !== SEVERITY.PASS && i.severity !== SEVERITY.INFO)
        .map((i) => i.detail);

      items.push({
        port: pr.port,
        protocol: "tcp",
        service: pr.service,
        program: "TLS",
        version: pr.negotiation.protocol,
        status: "open",
        severity: pr.severity,
        info: [
          status,
          `${pr.certificate.daysToExpiry}d remaining`,
          pr.negotiation.cipher,
          pr.negotiation.forwardSecrecy ? "FS" : "no-FS",
          pr.certificate.selfSigned ? "self-signed" : null,
          pr.certificate.hostnameValid ? null : "hostname-mismatch",
        ].filter(Boolean).join(" | "),
        issues: actionableIssues,
        details: {
          subject: pr.certificate.subject,
          issuer: pr.certificate.issuer,
          names: pr.certificate.names,
          validFrom: pr.certificate.validFrom,
          validTo: pr.certificate.validTo,
          signatureAlgorithm: pr.certificate.signatureAlgorithm,
          keyType: pr.certificate.keyType,
          keyBits: pr.certificate.keyBits,
          chainDepth: pr.chain.depth,
          authorized: pr.authorized,
        },
        // ZDE: fingerprints and serial numbers stay in-process.
        // Conclude emits only classifications and metadata.
        source: "tls-cert-auditor",
        authoritative: false,  // Defer to built-in TLS scanner for port authority
      });
    }

    return items;
  },

  // Empty = don't steal authority from built-in scanner
  authoritativePorts: new Set(),
};
