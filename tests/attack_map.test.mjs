import test from 'node:test';
import assert from 'node:assert/strict';

import {
  SERVICE_TECHNIQUE_MAP,
  CWE_TECHNIQUE_MAP,
  attackUrl,
  mapServiceToAttack,
  mapCveToAttack,
  getAllTechniques,
  cweToMitre,
  cwesToMitre,
} from '../utils/attack_map.mjs';

// ---------------------------------------------------------------------------
// attackUrl
// ---------------------------------------------------------------------------

test('attackUrl: simple technique ID (no sub-technique)', () => {
  assert.equal(attackUrl('T1190'), 'https://attack.mitre.org/techniques/T1190/');
});

test('attackUrl: sub-technique with dot notation converts to slash', () => {
  assert.equal(attackUrl('T1021.004'), 'https://attack.mitre.org/techniques/T1021/004/');
});

test('attackUrl: another sub-technique', () => {
  assert.equal(attackUrl('T1557.001'), 'https://attack.mitre.org/techniques/T1557/001/');
});

test('attackUrl: T1590.002 DNS sub-technique', () => {
  assert.equal(attackUrl('T1590.002'), 'https://attack.mitre.org/techniques/T1590/002/');
});

// ---------------------------------------------------------------------------
// mapServiceToAttack — SSH with CVE
// ---------------------------------------------------------------------------

test('mapServiceToAttack: SSH service with CVE maps to T1021.004', () => {
  const svc = { service: 'ssh', port: 22, cves: ['CVE-2023-48795'] };
  const result = mapServiceToAttack(svc);
  const ids = result.map(t => t.techniqueId);
  assert.ok(ids.includes('T1021.004'), `Expected T1021.004, got ${ids}`);
  // Verify url is present and correct
  const ssh = result.find(t => t.techniqueId === 'T1021.004');
  assert.equal(ssh.url, 'https://attack.mitre.org/techniques/T1021/004/');
});

// ---------------------------------------------------------------------------
// mapServiceToAttack — FTP anonymous login
// ---------------------------------------------------------------------------

test('mapServiceToAttack: FTP with anonymous login maps to T1078 and T1530', () => {
  const svc = { service: 'ftp', port: 21, anonymousLogin: true };
  const result = mapServiceToAttack(svc);
  const ids = result.map(t => t.techniqueId);
  assert.ok(ids.includes('T1078'), `Expected T1078, got ${ids}`);
  assert.ok(ids.includes('T1530'), `Expected T1530, got ${ids}`);
});

// ---------------------------------------------------------------------------
// mapServiceToAttack — DNS zone transfer
// ---------------------------------------------------------------------------

test('mapServiceToAttack: DNS with AXFR allowed maps to T1590.002', () => {
  const svc = { service: 'dns', port: 53, axfrAllowed: true };
  const result = mapServiceToAttack(svc);
  const ids = result.map(t => t.techniqueId);
  assert.ok(ids.includes('T1590.002'), `Expected T1590.002, got ${ids}`);
});

// ---------------------------------------------------------------------------
// mapServiceToAttack — SNMP default community
// ---------------------------------------------------------------------------

test('mapServiceToAttack: SNMP with default "public" community maps to T1078 and T1040', () => {
  const svc = { service: 'snmp', port: 161, protocol: 'udp', community: 'public' };
  const result = mapServiceToAttack(svc);
  const ids = result.map(t => t.techniqueId);
  assert.ok(ids.includes('T1078'), `Expected T1078, got ${ids}`);
  assert.ok(ids.includes('T1040'), `Expected T1040, got ${ids}`);
});

// ---------------------------------------------------------------------------
// mapServiceToAttack — HTTP dangerous methods
// ---------------------------------------------------------------------------

test('mapServiceToAttack: HTTP with dangerous methods maps to T1190', () => {
  const svc = { service: 'http', port: 80, dangerousMethods: ['PUT', 'DELETE'] };
  const result = mapServiceToAttack(svc);
  const ids = result.map(t => t.techniqueId);
  assert.ok(ids.includes('T1190'), `Expected T1190, got ${ids}`);
});

// ---------------------------------------------------------------------------
// mapServiceToAttack — TLS weakness
// ---------------------------------------------------------------------------

test('mapServiceToAttack: TLS with weak algorithms maps to T1557', () => {
  const svc = { service: 'https', port: 443, weakAlgorithms: ['RC4'] };
  const result = mapServiceToAttack(svc);
  const ids = result.map(t => t.techniqueId);
  assert.ok(ids.includes('T1557'), `Expected T1557, got ${ids}`);
});

// ---------------------------------------------------------------------------
// mapServiceToAttack — RDP exposure
// ---------------------------------------------------------------------------

test('mapServiceToAttack: RDP service maps to T1021.001', () => {
  const svc = { service: 'rdp', port: 3389 };
  const result = mapServiceToAttack(svc);
  const ids = result.map(t => t.techniqueId);
  assert.ok(ids.includes('T1021.001'), `Expected T1021.001, got ${ids}`);
});

// ---------------------------------------------------------------------------
// mapServiceToAttack — mDNS/LLMNR exposure
// ---------------------------------------------------------------------------

test('mapServiceToAttack: LLMNR service maps to T1557.001', () => {
  const svc = { service: 'llmnr', port: 5355 };
  const result = mapServiceToAttack(svc);
  const ids = result.map(t => t.techniqueId);
  assert.ok(ids.includes('T1557.001'), `Expected T1557.001, got ${ids}`);
});

// ---------------------------------------------------------------------------
// mapCveToAttack
// ---------------------------------------------------------------------------

test('mapCveToAttack: SSH CVE returns T1021.004', () => {
  const result = mapCveToAttack('CVE-2023-48795', 'ssh');
  const ids = result.map(t => t.techniqueId);
  assert.ok(ids.includes('T1021.004'));
});

test('mapCveToAttack: SMB CVE returns T1021.002', () => {
  const result = mapCveToAttack('CVE-2017-0144', 'smb');
  const ids = result.map(t => t.techniqueId);
  assert.ok(ids.includes('T1021.002'));
});

test('mapCveToAttack: HTTP CVE returns T1190', () => {
  const result = mapCveToAttack('CVE-2021-44228', 'http');
  const ids = result.map(t => t.techniqueId);
  assert.ok(ids.includes('T1190'));
});

// ---------------------------------------------------------------------------
// getAllTechniques — deduplication
// ---------------------------------------------------------------------------

test('getAllTechniques: deduplicates techniques across services', () => {
  const conclusion = {
    result: {
      services: [
        { service: 'ftp', port: 21, anonymousLogin: true },
        { service: 'ftp', port: 2121, anonymousLogin: true },
        { service: 'dns', port: 53, axfrAllowed: true },
      ],
    },
  };
  const result = getAllTechniques(conclusion);
  const ids = result.map(t => t.techniqueId);

  // T1078 and T1530 should appear only once despite two FTP services
  assert.equal(ids.filter(id => id === 'T1078').length, 1, 'T1078 should be deduplicated');
  assert.equal(ids.filter(id => id === 'T1530').length, 1, 'T1530 should be deduplicated');
  // DNS technique should also be present
  assert.ok(ids.includes('T1590.002'));
  // Every entry should have a url
  for (const t of result) {
    assert.ok(t.url, `Technique ${t.techniqueId} should have a url`);
  }
});

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

test('mapServiceToAttack: null/undefined returns empty array', () => {
  assert.deepEqual(mapServiceToAttack(null), []);
  assert.deepEqual(mapServiceToAttack(undefined), []);
});

test('mapServiceToAttack: empty service object returns empty array', () => {
  assert.deepEqual(mapServiceToAttack({}), []);
});

test('mapServiceToAttack: unknown service type with no findings returns empty', () => {
  const svc = { service: 'unknown', port: 9999 };
  assert.deepEqual(mapServiceToAttack(svc), []);
});

test('getAllTechniques: empty/missing conclusion returns empty array', () => {
  assert.deepEqual(getAllTechniques(null), []);
  assert.deepEqual(getAllTechniques({}), []);
  assert.deepEqual(getAllTechniques({ result: {} }), []);
  assert.deepEqual(getAllTechniques({ result: { services: [] } }), []);
});

test('SERVICE_TECHNIQUE_MAP has all expected keys', () => {
  const expected = [
    'ssh_cve', 'smb_cve', 'ftp_anonymous', 'dns_zone_transfer',
    'snmp_default', 'http_dangerous', 'privesc_cve', 'default_credentials',
    'tls_weakness', 'rdp_exposure', 'mdns_llmnr_exposure',
  ];
  for (const key of expected) {
    assert.ok(SERVICE_TECHNIQUE_MAP[key], `Missing key: ${key}`);
    assert.ok(Array.isArray(SERVICE_TECHNIQUE_MAP[key]), `${key} should be an array`);
  }
});

// ---------------------------------------------------------------------------
// cweToMitre — single CWE lookup
// ---------------------------------------------------------------------------

test('cweToMitre: known CWE-89 (SQLi) returns T1190', () => {
  const result = cweToMitre('CWE-89');
  assert.equal(result.length, 1);
  assert.equal(result[0].techniqueId, 'T1190');
});

test('cweToMitre: CWE-326 (weak crypto) returns T1557', () => {
  const result = cweToMitre('CWE-326');
  const ids = result.map(t => t.techniqueId);
  assert.ok(ids.includes('T1557'), `Expected T1557, got ${ids}`);
});

test('cweToMitre: CWE-798 (hard-coded creds) returns T1552.001', () => {
  const result = cweToMitre('CWE-798');
  assert.equal(result[0].techniqueId, 'T1552.001');
});

test('cweToMitre: CWE-22 (path traversal) returns T1083', () => {
  const result = cweToMitre('CWE-22');
  assert.equal(result[0].techniqueId, 'T1083');
});

test('cweToMitre: case-insensitive (lowercase cwe-89 still works)', () => {
  const result = cweToMitre('cwe-89');
  assert.equal(result[0].techniqueId, 'T1190');
});

test('cweToMitre: tolerates surrounding whitespace', () => {
  const result = cweToMitre('  CWE-89  ');
  assert.equal(result[0].techniqueId, 'T1190');
});

test('cweToMitre: unknown CWE returns empty array', () => {
  assert.deepEqual(cweToMitre('CWE-999999'), []);
});

test('cweToMitre: malformed input (no CWE- prefix) returns empty', () => {
  assert.deepEqual(cweToMitre('89'), []);
});

test('cweToMitre: null/undefined returns empty array', () => {
  assert.deepEqual(cweToMitre(null), []);
  assert.deepEqual(cweToMitre(undefined), []);
});

test('cweToMitre: non-string input returns empty array', () => {
  assert.deepEqual(cweToMitre(89), []);
  assert.deepEqual(cweToMitre({}), []);
  assert.deepEqual(cweToMitre([]), []);
});

test('cweToMitre: returns a fresh copy (not the static map array)', () => {
  // Mutating the returned array must not affect subsequent calls
  const a = cweToMitre('CWE-89');
  a.push({ techniqueId: 'POISON', name: 'should not persist' });
  const b = cweToMitre('CWE-89');
  assert.equal(b.length, 1, 'static map must not be mutated');
  assert.equal(b[0].techniqueId, 'T1190');
});

// ---------------------------------------------------------------------------
// cwesToMitre — array → deduped union
// ---------------------------------------------------------------------------

test('cwesToMitre: array of CWEs returns deduped union', () => {
  const result = cwesToMitre(['CWE-89', 'CWE-78']);
  const ids = result.map(t => t.techniqueId);
  assert.ok(ids.includes('T1190'), 'should include CWE-89 → T1190');
  assert.ok(ids.includes('T1059'), 'should include CWE-78 → T1059');
});

test('cwesToMitre: deduplicates when multiple CWEs map to the same technique', () => {
  // CWE-326, CWE-327, CWE-328 all map to T1557
  const result = cwesToMitre(['CWE-326', 'CWE-327', 'CWE-328']);
  const t1557 = result.filter(t => t.techniqueId === 'T1557');
  assert.equal(t1557.length, 1, 'T1557 should be deduplicated');
});

test('cwesToMitre: filters unknown CWEs silently', () => {
  const result = cwesToMitre(['CWE-89', 'CWE-NOPE', 'CWE-999999']);
  const ids = result.map(t => t.techniqueId);
  assert.ok(ids.includes('T1190'));
  assert.equal(result.length, 1, 'unknowns should not contribute');
});

test('cwesToMitre: empty array returns empty', () => {
  assert.deepEqual(cwesToMitre([]), []);
});

test('cwesToMitre: null/undefined returns empty', () => {
  assert.deepEqual(cwesToMitre(null), []);
  assert.deepEqual(cwesToMitre(undefined), []);
});

test('cwesToMitre: accepts a single string (not just arrays)', () => {
  const result = cwesToMitre('CWE-89');
  assert.equal(result[0].techniqueId, 'T1190');
});

// ---------------------------------------------------------------------------
// CWE fallback in mapServiceToAttack
// ---------------------------------------------------------------------------

test('mapServiceToAttack: applies CWE fallback when no CVEs', () => {
  const svc = { service: 'unknown', port: 9999, cwes: ['CWE-326'] };
  const result = mapServiceToAttack(svc);
  const ids = result.map(t => t.techniqueId);
  assert.ok(ids.includes('T1557'), `Expected CWE fallback T1557, got ${ids}`);
});

test('mapServiceToAttack: CWE fallback reads service.cwe (singular fallback)', () => {
  const svc = { service: 'unknown', port: 9999, cwe: ['CWE-89'] };
  const result = mapServiceToAttack(svc);
  const ids = result.map(t => t.techniqueId);
  assert.ok(ids.includes('T1190'));
});

test('mapServiceToAttack: CWE fallback reads service.evidence.cwe', () => {
  const svc = { service: 'unknown', port: 9999, evidence: { cwe: ['CWE-22'] } };
  const result = mapServiceToAttack(svc);
  const ids = result.map(t => t.techniqueId);
  assert.ok(ids.includes('T1083'), `Expected T1083 from evidence.cwe, got ${ids}`);
});

test('mapServiceToAttack: CWE fallback NOT applied when CVE mapping produced techniques', () => {
  // SSH service with CVE produces T1021.004 (CVE-derived). CWE-89 (would give T1190)
  // must NOT contribute because the fallback is gated.
  const svc = {
    service: 'ssh',
    port: 22,
    cves: ['CVE-2023-48795'],
    cwes: ['CWE-89'],
  };
  const result = mapServiceToAttack(svc);
  const ids = result.map(t => t.techniqueId);
  assert.ok(ids.includes('T1021.004'), 'CVE-derived T1021.004 should be present');
  assert.ok(!ids.includes('T1190'), 'CWE fallback should NOT have added T1190');
});

test('mapServiceToAttack: unknown service with no CVE/CWE returns empty', () => {
  const svc = { service: 'unknown', port: 9999 };
  assert.deepEqual(mapServiceToAttack(svc), []);
});

test('mapServiceToAttack: CWE fallback techniques get url field populated', () => {
  const svc = { service: 'unknown', port: 9999, cwes: ['CWE-326'] };
  const result = mapServiceToAttack(svc);
  const t1557 = result.find(t => t.techniqueId === 'T1557');
  assert.ok(t1557, 'T1557 should be present');
  assert.equal(t1557.url, 'https://attack.mitre.org/techniques/T1557/');
});

test('mapServiceToAttack: CWE fallback dedups against service-flag techniques', () => {
  // tls_weakness flag also produces T1557. CWE-326 also maps to T1557.
  // But CWE fallback only fires when there are NO CVEs, so we test the path
  // where service flags + CWE coexist without CVEs.
  const svc = {
    service: 'https',
    port: 443,
    weakProtocols: ['TLSv1.0'],
    cwes: ['CWE-326'],
  };
  const result = mapServiceToAttack(svc);
  const t1557 = result.filter(t => t.techniqueId === 'T1557');
  assert.equal(t1557.length, 1, 'T1557 must be present exactly once after dedup');
});

// ---------------------------------------------------------------------------
// CWE_TECHNIQUE_MAP coverage
// ---------------------------------------------------------------------------

test('CWE_TECHNIQUE_MAP has at least 30 entries', () => {
  const count = Object.keys(CWE_TECHNIQUE_MAP).length;
  assert.ok(count >= 30, `Expected >= 30 CWE mappings, got ${count}`);
});

test('CWE_TECHNIQUE_MAP all entries follow CWE-NNN format', () => {
  for (const key of Object.keys(CWE_TECHNIQUE_MAP)) {
    assert.match(key, /^CWE-\d+$/, `Invalid CWE key format: ${key}`);
  }
});

test('CWE_TECHNIQUE_MAP all entries are non-empty arrays of techniques', () => {
  for (const [cwe, techs] of Object.entries(CWE_TECHNIQUE_MAP)) {
    assert.ok(Array.isArray(techs), `${cwe} should be an array`);
    assert.ok(techs.length > 0, `${cwe} should have at least one technique`);
    for (const t of techs) {
      assert.match(t.techniqueId, /^T\d+(\.\d+)?$/, `${cwe} has malformed techniqueId: ${t.techniqueId}`);
      assert.ok(t.name && typeof t.name === 'string', `${cwe} has invalid name`);
    }
  }
});
