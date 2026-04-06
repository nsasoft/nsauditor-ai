import test from 'node:test';
import assert from 'node:assert/strict';

import {
  SERVICE_TECHNIQUE_MAP,
  attackUrl,
  mapServiceToAttack,
  mapCveToAttack,
  getAllTechniques,
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
