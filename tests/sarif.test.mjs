import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

import { severityToLevel, buildSarifLog } from '../utils/sarif.mjs';

const require = createRequire(import.meta.url);
const { version: PKG_VERSION } = require('../package.json');

// ---------------------------------------------------------------------------
// severityToLevel
// ---------------------------------------------------------------------------

test('severityToLevel: Critical → error', () => {
  assert.equal(severityToLevel('Critical'), 'error');
});

test('severityToLevel: High → error', () => {
  assert.equal(severityToLevel('High'), 'error');
});

test('severityToLevel: Medium → warning', () => {
  assert.equal(severityToLevel('Medium'), 'warning');
});

test('severityToLevel: Low → note', () => {
  assert.equal(severityToLevel('Low'), 'note');
});

test('severityToLevel: Info → note', () => {
  assert.equal(severityToLevel('Info'), 'note');
});

test('severityToLevel: case insensitive', () => {
  assert.equal(severityToLevel('critical'), 'error');
  assert.equal(severityToLevel('HIGH'), 'error');
  assert.equal(severityToLevel('medium'), 'warning');
  assert.equal(severityToLevel('low'), 'note');
  assert.equal(severityToLevel('info'), 'note');
});

test('severityToLevel: unknown/empty → note', () => {
  assert.equal(severityToLevel(''), 'note');
  assert.equal(severityToLevel(null), 'note');
  assert.equal(severityToLevel(undefined), 'note');
  assert.equal(severityToLevel('banana'), 'note');
});

// ---------------------------------------------------------------------------
// buildSarifLog — structure
// ---------------------------------------------------------------------------

test('buildSarifLog: produces valid SARIF structure', () => {
  const sarif = buildSarifLog({
    host: '192.168.1.1',
    conclusion: { result: { services: [] } }
  });

  assert.equal(sarif.version, '2.1.0');
  assert.ok(sarif.$schema.includes('sarif-schema-2.1.0'));
  assert.ok(Array.isArray(sarif.runs));
  assert.equal(sarif.runs.length, 1);

  const run = sarif.runs[0];
  assert.equal(run.tool.driver.name, 'nsauditor');
  assert.equal(run.tool.driver.version, PKG_VERSION);
  assert.ok(run.tool.driver.informationUri);
  assert.ok(Array.isArray(run.tool.driver.rules));
  assert.ok(Array.isArray(run.results));
});

test('buildSarifLog: no services → empty results', () => {
  const sarif = buildSarifLog({
    host: '10.0.0.1',
    conclusion: { result: { services: [] } }
  });

  assert.equal(sarif.runs[0].results.length, 0);
  assert.equal(sarif.runs[0].tool.driver.rules.length, 0);
});

test('buildSarifLog: null/missing conclusion → empty results', () => {
  const sarif = buildSarifLog({
    host: '10.0.0.1',
    conclusion: null
  });

  assert.equal(sarif.runs[0].results.length, 0);
});

// ---------------------------------------------------------------------------
// buildSarifLog — service mapping
// ---------------------------------------------------------------------------

test('buildSarifLog: maps services to results', () => {
  const sarif = buildSarifLog({
    host: '10.0.0.1',
    conclusion: {
      result: {
        services: [
          {
            port: 22,
            protocol: 'tcp',
            service: 'ssh',
            program: 'OpenSSH',
            version: '8.9',
            status: 'open',
            info: 'SSH-2.0-OpenSSH_8.9',
            banner: 'SSH-2.0-OpenSSH_8.9',
            source: 'ssh',
            evidence: []
          },
          {
            port: 80,
            protocol: 'tcp',
            service: 'http',
            program: 'nginx',
            version: '1.18.0',
            status: 'open',
            info: null,
            banner: null,
            source: 'http',
            evidence: []
          }
        ]
      }
    }
  });

  const run = sarif.runs[0];
  assert.equal(run.results.length, 2);

  // First result: SSH
  assert.equal(run.results[0].ruleId, 'openssh:8.9');
  assert.ok(run.results[0].message.text.includes('ssh'));
  assert.ok(run.results[0].message.text.includes('10.0.0.1'));
  assert.equal(run.results[0].locations[0].physicalLocation.artifactLocation.uri, '10.0.0.1');

  // Second result: HTTP
  assert.equal(run.results[1].ruleId, 'nginx:1.18.0');
});

test('buildSarifLog: service with unknown program uses service name as rule ID', () => {
  const sarif = buildSarifLog({
    host: '10.0.0.1',
    conclusion: {
      result: {
        services: [{
          port: 443, protocol: 'tcp', service: 'https',
          program: 'Unknown', version: 'Unknown',
          status: 'open', info: null, banner: null,
          source: 'http', evidence: []
        }]
      }
    }
  });

  assert.equal(sarif.runs[0].results[0].ruleId, 'https');
});

// ---------------------------------------------------------------------------
// buildSarifLog — security findings
// ---------------------------------------------------------------------------

test('buildSarifLog: anonymousLogin creates error result', () => {
  const sarif = buildSarifLog({
    host: '10.0.0.1',
    conclusion: {
      result: {
        services: [{
          port: 21, protocol: 'tcp', service: 'ftp',
          program: 'vsftpd', version: '3.0.3',
          status: 'open', info: null, banner: '220 (vsFTPd 3.0.3)',
          anonymousLogin: true,
          source: 'ftp', evidence: []
        }]
      }
    }
  });

  const run = sarif.runs[0];
  const anonResult = run.results.find(r => r.ruleId === 'ftp-anonymous-login');
  assert.ok(anonResult, 'Should have ftp-anonymous-login result');
  assert.equal(anonResult.level, 'error');
  assert.ok(anonResult.message.text.includes('anonymous'));

  const anonRule = run.tool.driver.rules.find(r => r.id === 'ftp-anonymous-login');
  assert.ok(anonRule, 'Should have ftp-anonymous-login rule');
});

test('buildSarifLog: axfrAllowed creates error result', () => {
  const sarif = buildSarifLog({
    host: '10.0.0.1',
    conclusion: {
      result: {
        services: [{
          port: 53, protocol: 'udp', service: 'dns',
          program: 'BIND', version: '9.18',
          status: 'open', info: 'DNS reply', banner: null,
          axfrAllowed: true,
          source: 'dns', evidence: []
        }]
      }
    }
  });

  const run = sarif.runs[0];
  const axfrResult = run.results.find(r => r.ruleId === 'dns-zone-transfer');
  assert.ok(axfrResult, 'Should have dns-zone-transfer result');
  assert.equal(axfrResult.level, 'error');
  assert.ok(axfrResult.message.text.includes('AXFR'));
});

test('buildSarifLog: weakAlgorithms creates warning results', () => {
  const sarif = buildSarifLog({
    host: '10.0.0.1',
    conclusion: {
      result: {
        services: [{
          port: 22, protocol: 'tcp', service: 'ssh',
          program: 'OpenSSH', version: '7.4',
          status: 'open', info: null, banner: null,
          weakAlgorithms: ['diffie-hellman-group1-sha1', 'hmac-sha1'],
          source: 'ssh', evidence: []
        }]
      }
    }
  });

  const run = sarif.runs[0];
  const weakResults = run.results.filter(r => r.ruleId.startsWith('weak-algorithm-'));
  assert.equal(weakResults.length, 2);
  assert.ok(weakResults.every(r => r.level === 'warning'));

  const dh1 = weakResults.find(r => r.ruleId.includes('diffie-hellman-group1-sha1'));
  assert.ok(dh1, 'Should have result for diffie-hellman-group1-sha1');
  assert.ok(dh1.message.text.includes('diffie-hellman-group1-sha1'));
});

test('buildSarifLog: dangerousMethods creates warning results', () => {
  const sarif = buildSarifLog({
    host: '10.0.0.1',
    conclusion: {
      result: {
        services: [{
          port: 80, protocol: 'tcp', service: 'http',
          program: 'Apache', version: '2.4.41',
          status: 'open', info: null, banner: null,
          dangerousMethods: ['PUT', 'DELETE'],
          source: 'http', evidence: []
        }]
      }
    }
  });

  const run = sarif.runs[0];
  const methodResults = run.results.filter(r => r.ruleId.startsWith('http-dangerous-method-'));
  assert.equal(methodResults.length, 2);
  assert.ok(methodResults.every(r => r.level === 'warning'));

  const putResult = methodResults.find(r => r.ruleId === 'http-dangerous-method-put');
  assert.ok(putResult, 'Should have result for PUT method');
});

test('buildSarifLog: anonymousLogin false does not create finding', () => {
  const sarif = buildSarifLog({
    host: '10.0.0.1',
    conclusion: {
      result: {
        services: [{
          port: 21, protocol: 'tcp', service: 'ftp',
          program: 'vsftpd', version: '3.0.3',
          status: 'open', info: null, banner: null,
          anonymousLogin: false,
          source: 'ftp', evidence: []
        }]
      }
    }
  });

  const anonResult = sarif.runs[0].results.find(r => r.ruleId === 'ftp-anonymous-login');
  assert.equal(anonResult, undefined, 'Should NOT have ftp-anonymous-login result when false');
});

// ---------------------------------------------------------------------------
// buildSarifLog — realistic conclusion with mixed findings
// ---------------------------------------------------------------------------

test('buildSarifLog: realistic conclusion with multiple security findings', () => {
  const sarif = buildSarifLog({
    host: '192.168.1.100',
    conclusion: {
      result: {
        summary: 'Host is UP — OS: Linux — Open: ssh/22, ftp/21, http/80',
        host: { up: true, os: 'Linux', osVersion: null },
        services: [
          {
            port: 22, protocol: 'tcp', service: 'ssh',
            program: 'OpenSSH', version: '7.4',
            status: 'open',
            info: 'SSH-2.0-OpenSSH_7.4', banner: 'SSH-2.0-OpenSSH_7.4',
            weakAlgorithms: ['diffie-hellman-group1-sha1'],
            source: 'ssh', evidence: []
          },
          {
            port: 21, protocol: 'tcp', service: 'ftp',
            program: 'vsftpd', version: '3.0.3',
            status: 'open',
            info: '220 (vsFTPd 3.0.3)', banner: '220 (vsFTPd 3.0.3)',
            anonymousLogin: true,
            source: 'ftp', evidence: []
          },
          {
            port: 80, protocol: 'tcp', service: 'http',
            program: 'Apache', version: '2.4.29',
            status: 'open',
            info: null, banner: null,
            dangerousMethods: ['TRACE'],
            source: 'http', evidence: []
          },
          {
            port: 53, protocol: 'udp', service: 'dns',
            program: 'BIND', version: '9.11',
            status: 'open',
            info: 'DNS reply', banner: null,
            axfrAllowed: true,
            source: 'dns', evidence: []
          }
        ],
        evidence: []
      }
    }
  });

  const run = sarif.runs[0];

  // 4 base service results + 1 anonymousLogin + 1 axfrAllowed + 1 weakAlgorithm + 1 dangerousMethod = 8
  assert.equal(run.results.length, 8);

  // Verify all rule IDs are unique in the rules array
  const ruleIds = run.tool.driver.rules.map(r => r.id);
  assert.equal(ruleIds.length, new Set(ruleIds).size, 'Rule IDs should be unique');

  // Verify error-level findings
  const errors = run.results.filter(r => r.level === 'error');
  assert.ok(errors.length >= 2, 'Should have at least 2 error-level findings (anon + axfr)');

  // Verify warning-level findings
  const warnings = run.results.filter(r => r.level === 'warning');
  assert.ok(warnings.length >= 2, 'Should have at least 2 warning-level findings (weak algo + dangerous method)');

  // All results should have host as location
  for (const result of run.results) {
    assert.equal(result.locations[0].physicalLocation.artifactLocation.uri, '192.168.1.100');
  }
});
