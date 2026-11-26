# NSAuditor AI Scan Report

- **Host:** 192.0.2.10
- **Scan time:** 2026-11-26T00:00:00.000Z
- **Tool version:** m

## Summary

Host is UP — Open: tribe-v2/8080

- **Services detected:** 1
- **Security findings:** 41 (Critical: 12, High: 16, Medium: 8, Low: 5)
- **Scope:** counts only these service-check findings: anonymous FTP login (tested only when FTP_CHECK_ANON is set), a DNS zone transfer — whether this host serves the DNS_AXFR_DOMAIN zone to anyone who asks (tested only when DNS_CHECK_AXFR and DNS_AXFR_DOMAIN are set), an SNMP default community, weak SSH algorithms, weak TLS protocols, weak TLS ciphers (the cipher each version negotiated), dangerous HTTP methods (only where an Allow header was read), a self-signed certificate, an expired certificate, an SMB null session (tested only when SMB_NULL_SESSION is set), the MCP server checks, the TLS-certificate audit (040), the debug-endpoint audit (050), the DNS-security audit of the domain (060; its zone-transfer attempt — whether each of the domain's nameservers serves the zone to anyone — only when DNS_AUDIT_AXFR_CHECK is set). The opt-in checks are off by default. It does not look up CVEs, and does not include Enterprise analysis-agent findings or exploit intelligence (a CLI scan with the Enterprise package and a Pro or Enterprise licence records CVE and agent findings in scan_finding_queue.json, when there are any).

## Services

| Port | Protocol | Service | Program | Version | Status |
|------|----------|---------|---------|---------|--------|
| 8080 | tcp | tribe-v2 |  |  | open |

## Findings

### [Critical] Debug endpoint: /debug is accessible (HTTP 200) – Debug root

- **Target:** 192.0.2.10:8080/tcp

### [Critical] Debug endpoint: /debug/vars is accessible (HTTP 200) – Go expvar

- **Target:** 192.0.2.10:8080/tcp

### [Critical] Debug endpoint: /debug/pprof is accessible (HTTP 200) – Go pprof profiler

- **Target:** 192.0.2.10:8080/tcp

### [Critical] Debug endpoint: /debug/pprof/heap is accessible (HTTP 200) – Heap profile

- **Target:** 192.0.2.10:8080/tcp

### [Critical] Debug endpoint: /debug/requests is accessible (HTTP 200) – Request traces

- **Target:** 192.0.2.10:8080/tcp

### [Critical] Debug endpoint: /graphiql is accessible (HTTP 200) – GraphiQL IDE

- **Target:** 192.0.2.10:8080/tcp

### [Critical] Debug endpoint: /.env is accessible (HTTP 200) – Environment file

- **Target:** 192.0.2.10:8080/tcp

### [Critical] Debug endpoint: /config is accessible (HTTP 200) – Config endpoint

- **Target:** 192.0.2.10:8080/tcp

### [Critical] Debug endpoint: /actuator/env is accessible (HTTP 200) – Actuator env dump

- **Target:** 192.0.2.10:8080/tcp

### [Critical] Debug endpoint: /\_debug/neural-gate is accessible (HTTP 200) – TRIBE Neural Gate debug

- **Target:** 192.0.2.10:8080/tcp

### [Critical] Debug endpoint: /api/v1/debug is accessible (HTTP 200) – API debug route

- **Target:** 192.0.2.10:8080/tcp

### [Critical] Debug endpoint: /api/v2/debug is accessible (HTTP 200) – API v2 debug route

- **Target:** 192.0.2.10:8080/tcp

### [High] Debug endpoint: /metrics is accessible (HTTP 200) – Prometheus metrics

- **Target:** 192.0.2.10:8080/tcp

### [High] Debug endpoint: /graphql is accessible (HTTP 200) – GraphQL (introspection?)

- **Target:** 192.0.2.10:8080/tcp

### [High] Debug endpoint: /admin is accessible (HTTP 200) – Admin panel

- **Target:** 192.0.2.10:8080/tcp

### [High] Debug endpoint: /internal is accessible (HTTP 200) – Internal routes

- **Target:** 192.0.2.10:8080/tcp

### [High] Debug endpoint: /actuator is accessible (HTTP 200) – Spring Boot Actuator

- **Target:** 192.0.2.10:8080/tcp

### [High] Debug endpoint: /actuator/beans is accessible (HTTP 200) – Actuator beans

- **Target:** 192.0.2.10:8080/tcp

### [High] Debug endpoint: /trace is accessible (HTTP 200) – Trace endpoint

- **Target:** 192.0.2.10:8080/tcp

### [High] Debug endpoint: /\_\_trace is accessible (HTTP 200) – Hidden trace

- **Target:** 192.0.2.10:8080/tcp

### [High] Debug endpoint: /api/v1/users returns 200 without authentication

- **Target:** 192.0.2.10:8080/tcp

### [High] Debug endpoint: /api/v1/scan returns 200 without authentication

- **Target:** 192.0.2.10:8080/tcp

### [High] Debug endpoint: /api/v1/results returns 200 without authentication

- **Target:** 192.0.2.10:8080/tcp

### [High] Debug endpoint: /api/v2/neural returns 200 without authentication

- **Target:** 192.0.2.10:8080/tcp

### [High] Debug endpoint: /api/v2/agents returns 200 without authentication

- **Target:** 192.0.2.10:8080/tcp

### [High] Debug endpoint: /api/v2/config returns 200 without authentication

- **Target:** 192.0.2.10:8080/tcp

### [High] Debug endpoint: /api/v1/admin returns 200 without authentication

- **Target:** 192.0.2.10:8080/tcp

### [High] Debug endpoint: /api/v1/plugins returns 200 without authentication

- **Target:** 192.0.2.10:8080/tcp

### [Medium] Debug endpoint: /swagger is accessible (HTTP 200) – Swagger docs

- **Target:** 192.0.2.10:8080/tcp

### [Medium] Debug endpoint: /swagger-ui is accessible (HTTP 200) – Swagger UI

- **Target:** 192.0.2.10:8080/tcp

### [Medium] Debug endpoint: /swagger.json is accessible (HTTP 200) – Swagger spec

- **Target:** 192.0.2.10:8080/tcp

### [Medium] Debug endpoint: /openapi.json is accessible (HTTP 200) – OpenAPI spec

- **Target:** 192.0.2.10:8080/tcp

### [Medium] Debug endpoint: /api-docs is accessible (HTTP 200) – API documentation

- **Target:** 192.0.2.10:8080/tcp

### [Medium] Debug endpoint: /server-info is accessible (HTTP 200) – Server info

- **Target:** 192.0.2.10:8080/tcp

### [Medium] Debug endpoint: HSTS not set — no forced HTTPS

- **Target:** 192.0.2.10:8080/tcp

### [Medium] Debug endpoint: CSP not set — XSS risk increased

- **Target:** 192.0.2.10:8080/tcp

### [Low] Debug endpoint: /docs is accessible (HTTP 200) – Documentation

- **Target:** 192.0.2.10:8080/tcp

### [Low] Debug endpoint: /info is accessible (HTTP 200) – Info endpoint

- **Target:** 192.0.2.10:8080/tcp

### [Low] Debug endpoint: X-Content-Type-Options missing — MIME sniffing possible

- **Target:** 192.0.2.10:8080/tcp

### [Low] Debug endpoint: X-Frame-Options missing — clickjacking possible

- **Target:** 192.0.2.10:8080/tcp

### [Low] Debug endpoint: Referrer-Policy missing

- **Target:** 192.0.2.10:8080/tcp
