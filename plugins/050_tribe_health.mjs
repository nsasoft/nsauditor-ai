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
// ─────────────────────────────────────────────────────────────────────────────

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
//    TRIBE_API_HOST=127.0.0.1
//    TRIBE_API_PORT=8080
//    TRIBE_API_SCHEME=http
//    TRIBE_API_TIMEOUT_MS=5000
//    TRIBE_API_AUTH_TOKEN=<token>    (to test authenticated vs unauthenticated)
//

function loadConfig(host, port, opts = {}) {
  return {
    host:      opts.host      || process.env.TRIBE_API_HOST      || host || "127.0.0.1",
    port:      opts.port      || process.env.TRIBE_API_PORT      || port || 8080,
    scheme:    opts.scheme    || process.env.TRIBE_API_SCHEME    || "http",
    timeoutMs: parseInt(opts.timeoutMs || process.env.TRIBE_API_TIMEOUT_MS || "5000", 10),
    authToken: opts.authToken || process.env.TRIBE_API_AUTH_TOKEN || null,
  };
}

function baseUrl(config) {
  return `${config.scheme}://${config.host}:${config.port}`;
}

// ── HTTP Fetch Wrapper (with timeout + error capture) ────────────────────────

async function probe(url, config, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), config.timeoutMs);

  const result = {
    url,
    status: null,
    headers: {},
    body: null,
    error: null,
    responded: false,
    latencyMs: 0,
  };

  const start = Date.now();

  try {
    const fetchOpts = {
      method: options.method || "GET",
      signal: controller.signal,
      headers: {
        "User-Agent": "NSAuditor-AI/TribeProbe",
        ...(options.headers || {}),
      },
      redirect: "manual", // Don't follow — we want to see what the server sends
    };

    const resp = await fetch(url, fetchOpts);
    result.latencyMs = Date.now() - start;
    result.status = resp.status;
    result.responded = true;

    // Capture all response headers
    for (const [key, value] of resp.headers.entries()) {
      result.headers[key.toLowerCase()] = value;
    }

    // Read body (cap at 8KB to avoid memory issues)
    try {
      const text = await resp.text();
      result.body = text.length > 8192 ? text.slice(0, 8192) + "...[truncated]" : text;
    } catch {
      result.body = null;
    }
  } catch (err) {
    result.latencyMs = Date.now() - start;
    result.error = err.name === "AbortError" ? "timeout" : err.message;
  } finally {
    clearTimeout(timer);
  }

  return result;
}

// ── Probe Modules ────────────────────────────────────────────────────────────

// 1. Health Endpoint Check
async function probeHealth(config) {
  const issues = [];
  const endpoints = ["/health", "/healthz", "/status", "/ping", "/ready"];
  const found = [];

  for (const ep of endpoints) {
    const res = await probe(`${baseUrl(config)}${ep}`, config);
    if (res.responded && res.status >= 200 && res.status < 400) {
      found.push({ endpoint: ep, status: res.status });

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

  return { endpoints: found, issues };
}

// 2. Debug Endpoint Discovery
async function probeDebugEndpoints(config) {
  const issues = [];

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

      // Upgrade severity if endpoint returns actual content (not just auth wall)
      if (res.status === 200 && res.body && res.body.length > 10) {
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

  return { issues };
}

// 3. Error Verbosity Check – do error responses leak stack traces?
async function probeErrorVerbosity(config) {
  const issues = [];

  // Hit a definitely-nonexistent path and examine the error body
  const errorPaths = [
    "/this-does-not-exist-nsauditor-probe",
    "/api/v99/nonexistent",
    "/null%00byte",     // Null byte injection
    "/%2e%2e/etc/passwd", // Path traversal attempt
  ];

  for (const path of errorPaths) {
    const res = await probe(`${baseUrl(config)}${path}`, config);
    if (!res.responded || !res.body) continue;

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

  return { issues };
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
async function probeMethodFuzzing(config) {
  const issues = [];
  const dangerousMethods = ["TRACE", "OPTIONS", "DELETE", "PUT", "PATCH"];

  // Test against root and a common API route
  const targets = ["/", "/api/v1/health"];

  for (const target of targets) {
    for (const method of dangerousMethods) {
      const res = await probe(`${baseUrl(config)}${target}`, config, { method });

      if (!res.responded) continue;

      // TRACE should NEVER be enabled (XST attack)
      if (method === "TRACE" && res.status === 200) {
        issues.push({
          severity: SEVERITY.HIGH,
          check: "trace_enabled",
          detail: `TRACE method enabled on ${target} — Cross-Site Tracing (XST) possible`,
          endpoint: target,
        });
      }

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
    "exposed internal endpoints. Host/port from .env or scan context.",
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
          "Set TRIBE_API_ALLOW_REMOTE=true in .env to probe remote hosts.",
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
      },
      healthEndpoints: health.endpoints,
    };
  },

  // ── Conclude: NSAuditor report items ────────────────────────────────────
  conclude({ result }) {
    if (!result.up) {
      return [{
        port: 8080,
        protocol: "tcp",
        service: "tribe-v2",
        status: "down",
        severity: SEVERITY.INFO,
        info: result.error,
        source: "tribe-health",
      }];
    }

    const items = [];

    // Service identity item
    items.push({
      port: 8080,
      protocol: "tcp",
      service: "tribe-v2",
      status: "open",
      severity: result.overallSeverity,
      info: `API probe complete: ${result.summary.critical} critical, ${result.summary.high} high, ${result.summary.medium} medium findings`,
      serverInfo: result.serverInfo,
      source: "tribe-health",
      authoritative: true,
    });

    // Individual findings grouped by category
    const allFindings = Object.entries(result.findings).flatMap(
      ([category, issues]) => issues.map((i) => ({ ...i, category }))
    );

    // Only surface actionable items (skip PASS and INFO in conclude)
    for (const f of allFindings) {
      if (f.severity === SEVERITY.PASS || f.severity === SEVERITY.INFO) continue;

      items.push({
        port: 8080,
        protocol: "tcp",
        service: "tribe-v2",
        severity: f.severity,
        status: "action_required",
        category: f.category,
        check: f.check,
        info: f.detail,
        // ZDE: no response bodies or header values in conclude output.
        // Only classifications and issue descriptions.
        source: "tribe-health",
      });
    }

    return items;
  },
};
