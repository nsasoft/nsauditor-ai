// plugins/050_tribe_health.mjs
// ─────────────────────────────────────────────────────────────────────────────
// NSAuditor AI – TRIBE v2 Neural API Security Probe
// Tier: Community (internal infrastructure check)
// Protocol: tcp / http
// ZDE: All probes target localhost/internal only. No external callbacks.
// ─────────────────────────────────────────────────────────────────────────────
//
// What this catches:
//   - Debug endpoints left open (/debug, /metrics, /graphql, /swagger, etc.)
//   - Stack traces / verbose error bodies in non-200 responses
//   - Version & server headers leaking internals
//   - Missing or overly permissive CORS
//   - Unauthenticated access to protected routes
//   - Missing security headers (CSP, HSTS, X-Content-Type-Options, etc.)
//   - Open /health or /version exposing build metadata
//
//
// Every request goes through utils/target_http.mjs (EE Z-1 C-4): node:http, one connection per request, no redirect
// followed, nothing decoded. A reply whose body the waist did not read (a coded reply, one over the 1 MiB cap, one whose
// body timed out or failed) is LISTED iff a check could not decide without that body — the record says so and the
// history comparison holds this plugin's vanished findings instead of reading them as resolved. (A debug 200 over the
// cap decides: its check asks only for more than 10 bytes.)
// ─────────────────────────────────────────────────────────────────────────────

import { requestTarget, MAX_TIMEOUT_MS } from "../utils/target_http.mjs";

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
//    TRIBE_API_HOST=127.0.0.1
//    TRIBE_API_PORT=8080
//    TRIBE_API_SCHEME=http
//    TRIBE_API_TIMEOUT_MS=5000
//    TRIBE_API_AUTH_TOKEN=<token>    (to test authenticated vs unauthenticated)
//

// An integer setting, read STRICTLY (v391 C4-R2): a number must be an integer, a string must be digits only after trim.
// parseInt and Number read "1e3", "30s", "5000ms" and "0x10" as OTHER numbers (1, 30, 5000, 16); here each one is NaN.
function strictInt(value) {
  if (typeof value === "number") return Number.isInteger(value) ? value : NaN;
  if (typeof value === "string" && /^\d+$/.test(value.trim())) return Number(value.trim());
  return NaN;
}

// The first SET source (v392 6(i)). An opts value is unset only when undefined or null — an explicit 0 is a value and is
// read strictly, never passed over. An environment value is unset when absent or "" ("   " is a value, and not digits).
// The scan's `port` argument is not read this way: the engine passes 0 under runStrategy "single"
// (plugin_manager.mjs:289-292), so there 0 means "no port" and `port || 8080` keeps that term's fallback.
function firstSet(optValue, envValue, fallback) {
  if (optValue !== undefined && optValue !== null) return optValue;
  if (envValue !== undefined && envValue !== "") return envValue;
  return fallback;
}

// A bad value is a TypeError naming what the operator set — never a host-down or "timeout" reading (S-4, v388 7).
function loadConfig(host, port, opts = {}) {
  const config = {
    host:      opts.host      || process.env.TRIBE_API_HOST      || host || "127.0.0.1",
    port:      strictInt(firstSet(opts.port, process.env.TRIBE_API_PORT, port || 8080)),
    scheme:    opts.scheme    || process.env.TRIBE_API_SCHEME    || "http",
    timeoutMs: strictInt(firstSet(opts.timeoutMs, process.env.TRIBE_API_TIMEOUT_MS, 5000)),
    authToken: opts.authToken || process.env.TRIBE_API_AUTH_TOKEN || null,
  };
  if (!Number.isInteger(config.timeoutMs) || config.timeoutMs < 1 || config.timeoutMs > MAX_TIMEOUT_MS) {
    throw new TypeError(`TRIBE_API_TIMEOUT_MS must be an integer number of milliseconds from 1 to ${MAX_TIMEOUT_MS}`);
  }
  if (!Number.isInteger(config.port) || config.port < 1 || config.port > 65535) {
    throw new TypeError("TRIBE_API_PORT (or the scan's port) must be an integer from 1 to 65535");
  }
  if (config.scheme !== "http" && config.scheme !== "https") {
    throw new TypeError('TRIBE_API_SCHEME must be "http" or "https"');
  }
  return config;
}

function baseUrl(config) {
  return `${config.scheme}://${config.host}:${config.port}`;
}

// ── HTTP Wrapper (the target HTTP waist; timeout + error capture) ─────────────
//
// `body` is the whole body (the waist caps it at 1 MiB and hands back no partial body), or null with `notRead` set to
// the waist's { reason[, encoding] } when the body was not read. `headers` are the target's own text, keys lowercased.
// A TypeError (a bad argument, an unbracketed IPv6 literal) propagates: it is not a reading of the host.

async function probe(url, config, options = {}) {
  const result = {
    url,
    method: options.method || "GET",
    status: null,
    headers: {},
    body: null,
    notRead: null,
    error: null,
    responded: false,
    latencyMs: 0,
  };

  const start = Date.now();

  try {
    const resp = await requestTarget(url, {
      method: options.method || "GET",
      headers: {
        "User-Agent": "NSAuditor-AI/TribeProbe",
        ...(options.headers || {}),
      },
      timeoutMs: config.timeoutMs,
    });
    result.latencyMs = Date.now() - start;
    result.status = resp.status;
    result.responded = true;
    result.headers = resp.headers;
    if (resp.notRead) result.notRead = resp.notRead;
    else result.body = resp.text;
  } catch (err) {
    if (err instanceof TypeError) throw err;
    result.latencyMs = Date.now() - start;
    result.error = err.name === "AbortError" ? "timeout" : err.message;
  }

  return result;
}

// One not-read entry: the plugin's own path constant, the method, the waist's reason and its mapped coding tokens.
// Nothing of the target's — no host, no status text, no header value.
function notReadEntry(path, res) {
  return {
    path,
    method: res.method,
    reason: res.notRead.reason,
    ...(Array.isArray(res.notRead.encoding) ? { encoding: res.notRead.encoding } : {}),
  };
}

// The coverage gap for the replies listed above (the 040 tlsCoverageGap shape): INFO, `details.evidenceGap`, shown as a
// gap and never counted. Its port is the port PROBED, the integer loadConfig read; the record key stays 8080 (G-67).
function tribeCoverageGap(notRead, port) {
  const n = notRead.length;
  return {
    severity: SEVERITY.INFO,
    check: "tribe_probe_not_read",
    title: `[COVERAGE GAP] TRIBE API probe: the body of ${n} ${n === 1 ? "reply" : "replies"} on port ${port} was not read`,
    detail:
      "A response began and its body was not read (a coded reply, a body over the 1 MiB cap, or a body that timed out " +
      "or failed): the checks that decide from that body did not run on those paths. This is not a pass. This list " +
      "names the replies whose body was not read where a check could not decide without it; a probe that got no " +
      "reply is not listed.",
    port,
    details: { evidenceGap: true, notRead },
  };
}

// ── Probe Modules ────────────────────────────────────────────────────────────

// 1. Health Endpoint Check
async function probeHealth(config) {
  const issues = [];
  const endpoints = ["/health", "/healthz", "/status", "/ping", "/ready"];
  const found = [];
  const notRead = [];

  for (const ep of endpoints) {
    const res = await probe(`${baseUrl(config)}${ep}`, config);
    if (res.responded && res.status >= 200 && res.status < 400) {
      found.push({ endpoint: ep, status: res.status });
      if (res.notRead) notRead.push(notReadEntry(ep, res));

      // Check if health endpoint leaks build info
      if (res.body) {
        const lower = res.body.toLowerCase();
        const leaks = [];
        if (/"(version|build|commit|sha|git_hash|revision)"/i.test(res.body)) leaks.push("version/build info");
        if (/"(hostname|node|pod|container)"/i.test(res.body)) leaks.push("infrastructure identifiers");
        if (/"(uptime|started_at|boot_time)"/i.test(res.body)) leaks.push("uptime data");
        if (/"(database|redis|postgres|mongo|elastic)"/i.test(res.body)) leaks.push("backend dependency names");
        if (/"(env|environment|stage)"\s*:\s*"(dev|staging|debug|test)"/i.test(res.body)) leaks.push("non-production environment flag");

        if (leaks.length > 0) {
          issues.push({
            severity: SEVERITY.MEDIUM,
            check: "health_info_leak",
            detail: `${ep} exposes: ${leaks.join(", ")}`,
            endpoint: ep,
          });
        }
      }
    }
  }

  return { endpoints: found, issues, notRead };
}

// 2. Debug Endpoint Discovery
async function probeDebugEndpoints(config) {
  const issues = [];
  const notRead = [];

  const dangerousEndpoints = [
    { path: "/debug",                severity: SEVERITY.CRITICAL, desc: "Debug root" },
    { path: "/debug/vars",           severity: SEVERITY.CRITICAL, desc: "Go expvar" },
    { path: "/debug/pprof",          severity: SEVERITY.CRITICAL, desc: "Go pprof profiler" },
    { path: "/debug/pprof/heap",     severity: SEVERITY.CRITICAL, desc: "Heap profile" },
    { path: "/debug/requests",       severity: SEVERITY.CRITICAL, desc: "Request traces" },
    { path: "/metrics",              severity: SEVERITY.HIGH,     desc: "Prometheus metrics" },
    { path: "/graphql",              severity: SEVERITY.HIGH,     desc: "GraphQL (introspection?)" },
    { path: "/graphiql",             severity: SEVERITY.CRITICAL, desc: "GraphiQL IDE" },
    { path: "/swagger",              severity: SEVERITY.MEDIUM,   desc: "Swagger docs" },
    { path: "/swagger-ui",           severity: SEVERITY.MEDIUM,   desc: "Swagger UI" },
    { path: "/swagger.json",         severity: SEVERITY.MEDIUM,   desc: "Swagger spec" },
    { path: "/openapi.json",         severity: SEVERITY.MEDIUM,   desc: "OpenAPI spec" },
    { path: "/api-docs",             severity: SEVERITY.MEDIUM,   desc: "API documentation" },
    { path: "/docs",                 severity: SEVERITY.LOW,      desc: "Documentation" },
    { path: "/.env",                 severity: SEVERITY.CRITICAL, desc: "Environment file" },
    { path: "/config",               severity: SEVERITY.CRITICAL, desc: "Config endpoint" },
    { path: "/admin",                severity: SEVERITY.HIGH,     desc: "Admin panel" },
    { path: "/internal",             severity: SEVERITY.HIGH,     desc: "Internal routes" },
    { path: "/actuator",             severity: SEVERITY.HIGH,     desc: "Spring Boot Actuator" },
    { path: "/actuator/env",         severity: SEVERITY.CRITICAL, desc: "Actuator env dump" },
    { path: "/actuator/beans",       severity: SEVERITY.HIGH,     desc: "Actuator beans" },
    { path: "/trace",                severity: SEVERITY.HIGH,     desc: "Trace endpoint" },
    { path: "/__trace",              severity: SEVERITY.HIGH,     desc: "Hidden trace" },
    { path: "/server-info",          severity: SEVERITY.MEDIUM,   desc: "Server info" },
    { path: "/info",                 severity: SEVERITY.LOW,      desc: "Info endpoint" },
    { path: "/_debug/neural-gate",   severity: SEVERITY.CRITICAL, desc: "TRIBE Neural Gate debug" },
    { path: "/api/v1/debug",         severity: SEVERITY.CRITICAL, desc: "API debug route" },
    { path: "/api/v2/debug",         severity: SEVERITY.CRITICAL, desc: "API v2 debug route" },
  ];

  for (const ep of dangerousEndpoints) {
    const res = await probe(`${baseUrl(config)}${ep.path}`, config);

    // Accessible = not 404, not 405, not connection refused
    if (res.responded && res.status !== 404 && res.status !== 405 && res.status !== 501) {
      const issue = {
        severity: ep.severity,
        check: "debug_endpoint_exposed",
        detail: `${ep.path} is accessible (HTTP ${res.status}) – ${ep.desc}`,
        endpoint: ep.path,
        httpStatus: res.status,
      };

      // Upgrade severity if endpoint returns actual content (not just auth wall) — decided by LENGTH alone (> 10). A 200
      // over the 1 MiB cap has proved that length, so it decides and takes the upgrade (v391 C4-R1). A 200 not read for
      // any other reason (coded, body timed out, body failed) could not decide: it is listed, and the finding keeps its
      // own severity.
      const overCap = res.notRead?.reason === "body-cap";
      if (res.status === 200 && res.notRead && !overCap) notRead.push(notReadEntry(ep.path, res));
      if (res.status === 200 && (overCap || (res.body && res.body.length > 10))) {
        issue.detail += " — returns content without authentication";
        if (SEVERITY_RANK[ep.severity] < SEVERITY_RANK[SEVERITY.CRITICAL]) {
          issue.severity = SEVERITY.CRITICAL;
        }
      }

      // Check if it's behind auth (401/403 is better than 200)
      if (res.status === 401 || res.status === 403) {
        issue.severity = SEVERITY.INFO;
        issue.detail += " (auth-gated, good)";
      }

      issues.push(issue);
    }
  }

  return { issues, notRead };
}

// 3. Error Verbosity Check – do error responses leak stack traces?
async function probeErrorVerbosity(config) {
  const issues = [];
  const notRead = [];

  // Hit a definitely-nonexistent path and examine the error body
  const errorPaths = [
    "/this-does-not-exist-nsauditor-probe",
    "/api/v99/nonexistent",
    "/null%00byte",     // Null byte injection
    "/%2e%2e/etc/passwd", // Path traversal attempt
  ];

  for (const path of errorPaths) {
    const res = await probe(`${baseUrl(config)}${path}`, config);
    if (!res.responded) continue;
    if (res.notRead) { notRead.push(notReadEntry(path, res)); continue; }
    if (!res.body) continue;

    const body = res.body;

    // Stack trace indicators
    const stackPatterns = [
      { pattern: /at\s+\S+\s+\(.*:\d+:\d+\)/i,       name: "Node.js stack trace" },
      { pattern: /Traceback \(most recent call last\)/i, name: "Python traceback" },
      { pattern: /at\s+.*\.java:\d+/i,                  name: "Java stack trace" },
      { pattern: /goroutine\s+\d+/i,                    name: "Go goroutine dump" },
      { pattern: /File\s+".*",\s+line\s+\d+/i,          name: "Python file reference" },
      { pattern: /\/home\/\w+\//i,                       name: "Home directory path" },
      { pattern: /\/usr\/src\/app\//i,                   name: "Container source path" },
      { pattern: /node_modules\//i,                      name: "node_modules path" },
      { pattern: /Error:.*\n\s+at /,                     name: "Full error + stack" },
    ];

    for (const { pattern, name } of stackPatterns) {
      if (pattern.test(body)) {
        issues.push({
          severity: SEVERITY.HIGH,
          check: "error_verbosity",
          detail: `Error response on ${path} leaks ${name}`,
          endpoint: path,
          httpStatus: res.status,
        });
      }
    }

    // Check for raw SQL errors
    if (/SQL|SELECT|INSERT|UPDATE|DELETE|WHERE|syntax error at or near/i.test(body)) {
      issues.push({
        severity: SEVERITY.CRITICAL,
        check: "sql_error_leak",
        detail: `Error response on ${path} exposes SQL statements or errors`,
        endpoint: path,
        httpStatus: res.status,
      });
    }

    // Check for raw internal error messages with class names
    if (/Exception|NullPointerException|TypeError|ReferenceError|SyntaxError/i.test(body) && body.length > 200) {
      issues.push({
        severity: SEVERITY.MEDIUM,
        check: "verbose_error_message",
        detail: `Error response on ${path} contains detailed exception info (${res.status})`,
        endpoint: path,
        httpStatus: res.status,
      });
    }
  }

  return { issues, notRead };
}

// 4. Response Header Security Audit
async function probeHeaders(config) {
  const issues = [];
  const res = await probe(`${baseUrl(config)}/`, config);
  if (!res.responded) return { issues };

  const h = res.headers;

  // Headers that SHOULD be present
  const requiredHeaders = [
    { name: "strict-transport-security",  severity: SEVERITY.MEDIUM, desc: "HSTS not set — no forced HTTPS" },
    { name: "x-content-type-options",     severity: SEVERITY.LOW,    desc: "X-Content-Type-Options missing — MIME sniffing possible" },
    { name: "x-frame-options",            severity: SEVERITY.LOW,    desc: "X-Frame-Options missing — clickjacking possible" },
    { name: "content-security-policy",    severity: SEVERITY.MEDIUM, desc: "CSP not set — XSS risk increased" },
    { name: "referrer-policy",            severity: SEVERITY.LOW,    desc: "Referrer-Policy missing" },
    { name: "permissions-policy",         severity: SEVERITY.INFO,   desc: "Permissions-Policy missing" },
  ];

  for (const req of requiredHeaders) {
    if (!h[req.name]) {
      issues.push({
        severity: req.severity,
        check: "missing_security_header",
        detail: req.desc,
        header: req.name,
      });
    }
  }

  // Headers that SHOULD NOT be present (information leaks)
  const dangerousHeaders = [
    { name: "server",            severity: SEVERITY.LOW,    desc: "Server header exposes: " },
    { name: "x-powered-by",     severity: SEVERITY.MEDIUM, desc: "X-Powered-By leaks framework: " },
    { name: "x-aspnet-version", severity: SEVERITY.MEDIUM, desc: "ASP.NET version exposed: " },
    { name: "x-debug-token",    severity: SEVERITY.HIGH,   desc: "Debug token present: " },
    { name: "x-debug-token-link", severity: SEVERITY.HIGH, desc: "Debug profiler link exposed: " },
  ];

  for (const d of dangerousHeaders) {
    if (h[d.name]) {
      issues.push({
        severity: d.severity,
        check: "leaky_header",
        detail: `${d.desc}${h[d.name]}`,
        header: d.name,
        value: h[d.name],
      });
    }
  }

  // CORS Analysis
  // Probe with a spoofed Origin to see what the server allows
  const corsRes = await probe(`${baseUrl(config)}/`, config, {
    headers: { "Origin": "https://evil-attacker.com" },
  });

  if (corsRes.responded) {
    const acao = corsRes.headers["access-control-allow-origin"];
    const acac = corsRes.headers["access-control-allow-credentials"];

    if (acao === "*") {
      issues.push({
        severity: SEVERITY.HIGH,
        check: "cors_wildcard",
        detail: "CORS allows any origin (Access-Control-Allow-Origin: *)",
      });
    } else if (acao === "https://evil-attacker.com") {
      issues.push({
        severity: SEVERITY.CRITICAL,
        check: "cors_reflection",
        detail: "CORS reflects arbitrary Origin — any site can make authenticated requests",
      });
      if (acac === "true") {
        issues.push({
          severity: SEVERITY.CRITICAL,
          check: "cors_credentials_reflection",
          detail: "CORS reflects Origin AND allows credentials — full cookie theft possible",
        });
      }
    }

    if (acao && acao !== "*" && acac === "true") {
      issues.push({
        severity: SEVERITY.MEDIUM,
        check: "cors_credentials",
        detail: `CORS allows credentials from: ${acao}`,
      });
    }
  }

  return { issues, headers: h };
}

// 5. Authentication Enforcement Check
async function probeAuthEnforcement(config) {
  const issues = [];

  // Routes that should require auth
  const protectedRoutes = [
    "/api/v1/users",
    "/api/v1/scan",
    "/api/v1/results",
    "/api/v2/neural",
    "/api/v2/agents",
    "/api/v2/config",
    "/api/v1/admin",
    "/api/v1/plugins",
  ];

  for (const route of protectedRoutes) {
    // First: hit without auth
    const noAuth = await probe(`${baseUrl(config)}${route}`, config);

    if (noAuth.responded && noAuth.status === 200) {
      issues.push({
        severity: SEVERITY.HIGH,
        check: "unauthenticated_access",
        detail: `${route} returns 200 without authentication`,
        endpoint: route,
      });
    }

    // If we have a token, verify it works (confirms the route exists)
    if (config.authToken && noAuth.responded && (noAuth.status === 401 || noAuth.status === 403)) {
      const withAuth = await probe(`${baseUrl(config)}${route}`, config, {
        headers: { "Authorization": `Bearer ${config.authToken}` },
      });

      if (withAuth.responded && withAuth.status === 200) {
        // Good: route exists, requires auth, and auth works
        issues.push({
          severity: SEVERITY.PASS,
          check: "auth_enforced",
          detail: `${route} correctly requires authentication`,
          endpoint: route,
        });
      }
    }
  }

  return { issues };
}

// 6. HTTP Method Fuzzing – are unexpected methods allowed?
// TRACE is not sent (the waist refuses it; the former client threw on it, so the TRACE check never ran). DELETE, PUT and PATCH are
// sent and their replies are not examined (operator decision O-3: keep the behaviour).
async function probeMethodFuzzing(config) {
  const issues = [];
  const dangerousMethods = ["OPTIONS", "DELETE", "PUT", "PATCH"];

  // Test against root and a common API route
  const targets = ["/", "/api/v1/health"];

  for (const target of targets) {
    for (const method of dangerousMethods) {
      const res = await probe(`${baseUrl(config)}${target}`, config, { method });

      if (!res.responded) continue;

      // OPTIONS is fine (CORS preflight) but check what it reveals
      if (method === "OPTIONS" && res.status === 200) {
        const allow = res.headers["allow"] || res.headers["access-control-allow-methods"];
        if (allow) {
          issues.push({
            severity: SEVERITY.INFO,
            check: "options_allow",
            detail: `${target} OPTIONS reveals allowed methods: ${allow}`,
            endpoint: target,
          });
        }
      }
    }
  }

  return { issues };
}

// ── Plugin Export ─────────────────────────────────────────────────────────────

export default {
  id: "050",
  name: "TRIBE v2 Neural API Security Probe",
  description:
    "Probes the TRIBE v2 API for debug leaks, stack traces in errors, " +
    "header security, CORS misconfiguration, unauthenticated routes, and " +
    "exposed internal endpoints. Host/port from the environment (exported or --env) or scan context.",
  priority: 300,
  tier: "community",  // Internal infra check — available to all tiers
  protocols: ["tcp", "http"],
  ports: [8080],

  requirements: {
    host: "up",
    tcp_open: [8080],
  },

  // ── Pre-flight ──────────────────────────────────────────────────────────
  preflight() {
    // No credentials required — this probes your own infra.
    // But warn if targeting non-localhost without explicit opt-in.
    const host = process.env.TRIBE_API_HOST || "127.0.0.1";
    const isLocal = ["127.0.0.1", "localhost", "::1", "0.0.0.0"].includes(host) ||
                    host.startsWith("10.") ||
                    host.startsWith("172.") ||
                    host.startsWith("192.168.");

    if (!isLocal && !process.env.TRIBE_API_ALLOW_REMOTE) {
      return {
        ready: false,
        reason:
          `TRIBE probe target is ${host} (non-local). ` +
          "Set TRIBE_API_ALLOW_REMOTE=true (export it, or put it in a file passed with --env) to probe remote hosts.",
      };
    }
    return { ready: true };
  },

  // ── Main Execution ──────────────────────────────────────────────────────
  async run(host, port, opts = {}) {
    const config = loadConfig(host, port, opts);
    const startTime = Date.now();

    // Quick connectivity check first
    const ping = await probe(`${baseUrl(config)}/`, config);
    if (!ping.responded) {
      return {
        up: false,
        error: `Cannot reach ${baseUrl(config)}: ${ping.error || "no response"}`,
        audit_type: "api_security_probe",
        duration_ms: Date.now() - startTime,
      };
    }

    // Run all probe modules
    const [health, debug, errors, headers, auth, methods] = await Promise.all([
      probeHealth(config),
      probeDebugEndpoints(config),
      probeErrorVerbosity(config),
      probeHeaders(config),
      probeAuthEnforcement(config),
      probeMethodFuzzing(config),
    ]);

    // The replies whose body was not read where a check could not decide without it. Not counted, never moves severity.
    const notRead = [...health.notRead, ...debug.notRead, ...errors.notRead];
    const coverageGap = notRead.length > 0 ? tribeCoverageGap(notRead, config.port) : null;

    // Aggregate all issues
    const allIssues = [
      ...health.issues,
      ...debug.issues,
      ...errors.issues,
      ...headers.issues,
      ...auth.issues,
      ...methods.issues,
    ];

    // Compute overall severity
    let overallSeverity = SEVERITY.PASS;
    for (const issue of allIssues) {
      if (SEVERITY_RANK[issue.severity] > SEVERITY_RANK[overallSeverity]) {
        overallSeverity = issue.severity;
      }
    }

    // Summary counts
    const summary = {
      totalChecks: allIssues.length,
      critical: allIssues.filter((i) => i.severity === SEVERITY.CRITICAL).length,
      high:     allIssues.filter((i) => i.severity === SEVERITY.HIGH).length,
      medium:   allIssues.filter((i) => i.severity === SEVERITY.MEDIUM).length,
      low:      allIssues.filter((i) => i.severity === SEVERITY.LOW).length,
      info:     allIssues.filter((i) => i.severity === SEVERITY.INFO).length,
      pass:     allIssues.filter((i) => i.severity === SEVERITY.PASS).length,
    };

    return {
      up: true,
      audit_type: "api_security_probe",
      target: baseUrl(config),
      overallSeverity,
      duration_ms: Date.now() - startTime,
      serverInfo: {
        initialStatus: ping.status,
        latencyMs: ping.latencyMs,
        server: headers.headers?.["server"] || "not disclosed",
        poweredBy: headers.headers?.["x-powered-by"] || "not disclosed",
      },
      summary,
      findings: {
        health:  health.issues,
        debug:   debug.issues,
        errors:  errors.issues,
        headers: headers.issues,
        auth:    auth.issues,
        methods: methods.issues,
        ...(coverageGap ? { coverage: [coverageGap] } : {}),
      },
      healthEndpoints: health.endpoints,
      details: { notRead },
    };
  },

  // ── Conclude: NSAuditor report items ────────────────────────────────────
  // 1.3.0: ONE record on 8080, its findings under `tribeHealth`. The per-finding records shared the summary's
  // protocol:port key and were dropped by the merge once the concluder reached this adapter — the CRITICAL among them.
  conclude({ result }) {
    if (!result.up) {
      // The API probe failed on a port the scan found open: that says nothing about the port's liveness.
      return [{
        port: 8080,
        protocol: "tcp",
        service: "tribe-v2",
        info: result.error,
        tribeHealth: { state: "down", severity: SEVERITY.INFO, error: result.error ?? null, findings: [] },
        source: "tribe-health",
      }];
    }

    // Individual findings grouped by category; only actionable ones (skip PASS and INFO in conclude). A coverage gap
    // (`details.evidenceGap`) is kept WHOLE although it is INFO: it is what says a check did not run.
    // What this output carries of the target: no response body, but the target's header text as received —
    // serverInfo.server and serverInfo.poweredBy, and the details of the leaky_header, cors_credentials and options_allow
    // findings (G-68). A not-read list carries only the plugin's own path, the method, the reason and coding tokens.
    const notRead = Array.isArray(result.details?.notRead) ? result.details.notRead : [];
    const findings = Object.entries(result.findings)
      .flatMap(([category, issues]) => issues.map((i) => ({ ...i, category })))
      .filter((f) => f.details?.evidenceGap === true || (f.severity !== SEVERITY.PASS && f.severity !== SEVERITY.INFO))
      .map((f) => (f.details?.evidenceGap === true ? f
        : { severity: f.severity, category: f.category, check: f.check, detail: f.detail }));
    const counts = `${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium findings`;
    const n = notRead.length;

    return [{
      port: 8080,
      protocol: "tcp",
      service: "tribe-v2",
      status: "open",
      info: n === 0
        ? `API probe complete: ${counts}`
        : `API probe incomplete: the body of ${n} ${n === 1 ? "reply" : "replies"} was not read; from the replies read, ${counts}`,
      tribeHealth: {
        state: "up", severity: result.overallSeverity, summary: result.summary, serverInfo: result.serverInfo, findings,
        ...(n > 0 ? { notRead } : {}),
      },
      source: "tribe-health",
      authoritative: true,
    }];
  },
};
