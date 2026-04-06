// tests/report_html.test.mjs
// Run with: npm test  (node --test)
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fsp from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { buildHtmlReport } from '../utils/report_html.mjs';

/* const SAMPLE_MD = `
## Detailed Vulnerability Analysis

| Vulnerability | Affected Asset/Port | Severity (Critical/High/Medium/Low) | CVSS v3.1 (if known) | CVE ID | Evidence (quote the exact line) |
|---|---|---|---|---|---|
| Example Vuln | 443/tcp | High | 7.5 | CVE-2023-12345 | "Server: OpenSSL 1.1.1" |

## Prioritized Remediation Plan
- Patch OpenSSL on 443/tcp. Priority: Medium.

For details visit https://example.com/security
`; */

const SAMPLE_MD = `
The security posture of the organization reveals several open services, including FTP, HTTP, HTTPS, DNS, SMTP, and MySQL, which could be targeted by malicious actors. There is one confirmed vulnerability associated with MySQL (CVE-2019-2929) due to its version being potentially outdated. The presence of exposed services increases the risk of unauthorized access and exploitation.

## Detailed Vulnerability Analysis

### Confirmed Vulnerabilities

| Vulnerability                               | Affected Asset/Port | Severity | CVSS v3.1 | CVE ID           | Evidence                                                                 |
|---------------------------------------------|----------------------|----------|------------|------------------|-------------------------------------------------------------------------|
| MySQL < 5.7.28 (Multiple vulnerabilities)   | MySQL on port 3306   | High     | 7.5        | CVE-2019-2929     | "MySQL greeting: 5.7.44"                                               |

### Leads (Needs Verification)

| Technology or Product              | Where Detected                     | What to Verify                                    | Why it Matters                                              |
|------------------------------------|------------------------------------|----------------------------------------------------|-----------------------------------------------------------|
| Pure-FTPd                          | FTP on port 21                     | Confirm version of Pure-FTPd                       | Old versions may have vulnerabilities that could be exploited.             |
| Apache HTTP Server + MySQL + PHP   | HTTP on port 80 and HTTPS on port 443 | Confirm versions of Apache HTTP Server, MySQL, and PHP | Unpatched versions can have significant vulnerabilities leading to data breaches. |
| Exim                                | SMTP on port 587                   | Confirm version of Exim                             | Vulnerabilities in outdated versions can lead to email exploitation.           |
| Dovecot                             | POP3 (110) and IMAP (143)          | Confirm versions of Dovecot                        | Outdated versions may have known vulnerabilities leading to unauthorized access.  |

## Risk Assessment
Not addressing the vulnerabilities identified could lead to significant business impact, including data breaches resulting from unauthorized access. The confirmed vulnerability in MySQL (CVE-2019-2929) exposes sensitive data to potential exploitation if not remediated. Similarly, the exposure of other services without verification of their versions can lead to further risks.

## Prioritized Remediation Plan
1. **Upgrade MySQL**: Upgrade to a secured version (>= 5.7.28).  
   **Rationale**: This version addresses critical vulnerabilities that can compromise data.  
   **Priority**: Critical.  
   **Timeline**: Immediate.  

2. **Verify and Update Pure-FTPd**: Retrieve the version of Pure-FTPd and upgrade if outdated.  
   **Rationale**: To mitigate the risk of FTP vulnerabilities.  
   **Priority**: High.  
   **Timeline**: Within 7 days.  

3. **Confirm Versions for Apache, MySQL, and PHP**: Check for updates and apply patches for vulnerabilities.  
   **Rationale**: Keeping these components updated minimizes the vulnerability footprint.  
   **Priority**: High.  
   **Timeline**: Within 7 days.  

4. **Verify Dovecot versions**: Confirm the version and upgrade if outdated.  
   **Rationale**: Vulnerabilities in email services can lead to data leakage.  
   **Priority**: Medium.  
   **Timeline**: Within 30 days.  

5. **Monitor Exim**: Confirm the Exim version and respond to any vulnerabilities accordingly.  
   **Rationale**: As an email server, it's crucial to ensure it is secured against known exploits.  
   **Priority**: Medium.  
   **Timeline**: Within 30 days.  

## Next Steps and Continuous Monitoring
- Conduct a re-scan of the network after implementing changes.
- Enable logging and alerts for all critical services.
- Inventory all exposed services to assess risks.
- Implement version tracking to maintain awareness of potential vulnerabilities.
- Schedule periodic WAF/IDS/IPS checks and regular audits to ensure security posture is maintained.

Reference: https://example.com/security
`;

test('buildHtmlReport returns a string (await required)', async () => {
  const html = await buildHtmlReport({
    host: '127.0.0.1',
    whenIso: '2025-08-29T12:00:00Z',
    model: 'unit-test',
    md: SAMPLE_MD
  });

  assert.equal(typeof html, 'string');
  assert.ok(html.startsWith('<!doctype html>'));
});

test('CVE tokens are linkified to NVD and bare URLs are linkified', async () => {
  const html = await buildHtmlReport({
    host: '127.0.0.1',
    whenIso: '2025-08-29T12:00:00Z',
    model: 'unit-test',
    md: SAMPLE_MD
  });

  assert.ok(html.includes('href="https://nvd.nist.gov/vuln/detail/CVE-2019-2929"'));
  assert.ok(html.includes('href="https://example.com/security"'));
  // no encoded anchors should survive
  assert.ok(!html.includes('&lt;a href='));
});

test('Severity/Priority badge machinery is present in the HTML (client-side transform)', async () => {
  const html = await buildHtmlReport({
    host: '127.0.0.1',
    whenIso: '2025-08-29T12:00:00Z',
    model: 'unit-test',
    md: SAMPLE_MD
  });

  // We can’t execute the browser script here, but we can assert the CSS/classes and script exist
  assert.ok(html.includes('.badge-high'), 'badge CSS for High severity missing');
 assert.ok(
  /(?:<strong>|<b>)?\s*Priority\s*(?:<\/strong>|<\/b>)?\s*[:\-—–]/i.test(html),
  'priority text not found'
);
  assert.ok(html.includes('<script>') && html.includes('Severity'), 'post-process script missing');
});

test('HTML can be written to disk (no Promise passed to writeFile)', async () => {
  const html = await buildHtmlReport({
    host: '127.0.0.1',
    whenIso: '2025-08-29T12:00:00Z',
    model: 'unit-test',
    md: SAMPLE_MD
  });
  const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), 'report-'));
  const p = path.join(tmp, 'report.html');

  await fsp.writeFile(p, html, 'utf8'); // this would fail if html were a Promise
  const stat = await fsp.stat(p);
  assert.ok(stat.isFile());
  assert.ok(stat.size > 100);
});
