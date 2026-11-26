# NSAuditor AI Scan Report

- **Host:** 192.0.2.10
- **Scan time:** 2026-11-26T00:00:00.000Z
- **Tool version:** m

## Summary

No evidence the host is up — No open services detected

- **Services detected:** 0
- **Security findings:** 0
- **Scope:** counts only these service-check findings: anonymous FTP login (tested only when FTP_CHECK_ANON is set), a DNS zone transfer — whether this host serves the DNS_AXFR_DOMAIN zone to anyone who asks (tested only when DNS_CHECK_AXFR and DNS_AXFR_DOMAIN are set), an SNMP default community, weak SSH algorithms, weak TLS protocols, weak TLS ciphers (the cipher each version negotiated), dangerous HTTP methods (only where an Allow header was read), a self-signed certificate, an expired certificate, an SMB null session (tested only when SMB_NULL_SESSION is set), the MCP server checks, the TLS-certificate audit (040), the debug-endpoint audit (050), the DNS-security audit of the domain (060; its zone-transfer attempt — whether each of the domain's nameservers serves the zone to anyone — only when DNS_AUDIT_AXFR_CHECK is set). The opt-in checks are off by default. It does not look up CVEs, and does not include Enterprise analysis-agent findings or exploit intelligence (a CLI scan with the Enterprise package and a Pro or Enterprise licence records CVE and agent findings in scan_finding_queue.json, when there are any).

## Services

_No services detected._

## Findings

_None of the counted service checks found anything. This is not a statement that the host has no known vulnerabilities — CVE lookups and analysis-agent findings are not part of this count (see Scope above), and anonymous FTP login, zone transfer and the SMB null session are tested only when enabled._
