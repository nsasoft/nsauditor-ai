// tests/dns_posture_caa_record_shape.test.mjs
// ─────────────────────────────────────────────────────────────────────────────
// THE CAA CHECK READS THE RECORD SHAPE NODE ACTUALLY RETURNS.
//
// `dns.promises.resolveCaa` returns one object per record, KEYED BY ITS TAG: `{ critical: 0, type: 'CAA', issue:
// 'pki.goog' }`, `{ …, issuewild: … }`, `{ …, iodef: 'mailto:…' }` — there is no `tag` and no `value` field. The CAA
// check read `r.tag` and `r.value`, so on real output it never saw an issue restriction (`caa_present` could not fire)
// and never saw an iodef tag (`caa_no_iodef` fired on every domain that publishes CAA, iodef or not).
//
// The fixtures are real answers, verbatim — the records three public domains publish, as node returned them — so the
// check is held to the resolver's shape and not to one a test author wrote. Every other lookup answers ENODATA.
//
// FOURTH QUADRANT FIRST: a domain with an issue restriction and NO iodef still reports the missing iodef — or the fix
// could pass by never reporting it.
// ─────────────────────────────────────────────────────────────────────────────
import './helpers/no_operator_home.mjs';
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const dnsP = require('node:dns').promises;
const net = require('node:net');

const ZONE = 'example.test';
let CAA = [];
const nodata = async (name) => { throw Object.assign(new Error(`query ENODATA ${name}`), { code: 'ENODATA' }); };
for (const k of ['resolve', 'resolve4', 'resolve6', 'resolveTxt', 'resolveCname', 'resolveMx', 'resolveNs', 'resolveSoa',
  'resolveAny']) dnsP[k] = nodata;
dnsP.resolveCaa = async (name) => (name === ZONE ? CAA : nodata(name));
net.createConnection = () => { throw new Error('no connection expected'); };

const { default: dnsSec } = await import('../plugins/060_dns_sec_auditor.mjs');

async function caaFindings(records) {
  CAA = records;
  const result = await dnsSec.run(ZONE, 0, {});
  return result.findings.caa.map((i) => ({ check: i.check, severity: i.severity, detail: i.detail }));
}
const checks = (fs) => fs.map((f) => `${f.check}:${f.severity}`).sort();

// Real answers (node's resolveCaa), verbatim.
const GOOGLE = [{ critical: 0, type: 'CAA', issue: 'pki.goog' }];
const MOZILLA = [{ critical: 0, type: 'CAA', issue: 'awstrust.com' }, { critical: 0, type: 'CAA', issue: 'pki.goog' },
  { critical: 0, type: 'CAA', issue: 'letsencrypt.org' }, { critical: 0, type: 'CAA', iodef: 'mailto:foxsec+caaiodef@mozilla.com' }];
const CLOUDFLARE = [{ critical: 0, type: 'CAA', issuewild: 'digicert.com; cansignhttpexchanges=yes' },
  { critical: 0, type: 'CAA', issuewild: 'letsencrypt.org' }, { critical: 0, type: 'CAA', iodef: 'mailto:tls-abuse@cloudflare.com' },
  { critical: 0, type: 'CAA', issue: 'comodoca.com' }, { critical: 0, type: 'CAA', issue: 'letsencrypt.org' }];

test('(first) an issue restriction with no iodef: CAA present, and the missing iodef is still reported', async () => {
  const fs = await caaFindings(GOOGLE);
  assert.deepEqual(checks(fs), ['caa_no_iodef:info', 'caa_present:pass']);
  assert.equal(fs.find((f) => f.check === 'caa_present').detail, 'CAA records restrict certificate issuance to: pki.goog');
});

test('an issue restriction WITH an iodef tag: CAA present, no iodef finding', async () => {
  const fs = await caaFindings(MOZILLA);
  assert.deepEqual(checks(fs), ['caa_present:pass']);
  assert.equal(fs[0].detail, 'CAA records restrict certificate issuance to: awstrust.com, pki.goog, letsencrypt.org');
});

test('issue and issuewild together, with an iodef tag: both restrictions are named, no iodef finding', async () => {
  const fs = await caaFindings(CLOUDFLARE);
  assert.deepEqual(checks(fs), ['caa_present:pass']);
  assert.equal(fs[0].detail, 'CAA records restrict certificate issuance to: digicert.com; cansignhttpexchanges=yes, '
    + 'letsencrypt.org, comodoca.com, letsencrypt.org');
});

test('an iodef tag alone: no issue restriction is claimed, and no iodef finding', async () => {
  assert.deepEqual(checks(await caaFindings([{ critical: 0, type: 'CAA', iodef: 'mailto:sec@example.test' }])), []);
});

test('no CAA records at all is still the measured no_caa', async () => {
  CAA = [];
  dnsP.resolveCaa = nodata;
  try {
    const result = await dnsSec.run(ZONE, 0, {});
    assert.deepEqual(result.findings.caa.map((i) => i.check), ['no_caa']);
  } finally {
    dnsP.resolveCaa = async (name) => (name === ZONE ? CAA : nodata(name));
  }
});
