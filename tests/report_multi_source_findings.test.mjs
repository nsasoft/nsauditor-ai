// tests/report_multi_source_findings.test.mjs
//
// THE REPORT OPENED ONE DOOR OUT OF FIVE, AND OVER A NETWORK SCAN THAT DOOR IS EMPTY.
//
// Gate 3-B, driven on the installed 0.44.0 trio against a real 192.168.1.1 run, produced
// the cardinal defect this product exists to prevent — a client deliverable certifying a
// vulnerable host as clean:
//
//     "No findings were recorded in this run."
//     "No findings recorded for this host."
//     CRITICAL 0 · HIGH 0 · MEDIUM 0 · LOW 0 · INFO 0 · PASS 0 · OTHER 0
//     CVE mentions in the rendered report: 0
//
// against 16 distinct CVEs including CVE-2020-25681 (dnsmasq 2.78, HIGH, epssScore 0.81,
// exploitPriority ELEVATED) — under a cover line promising findings "ordered by
// known-exploited first, then EPSS probability".
//
// `shapeHost` read `result.findings[]` and nothing else. Censused on that run, 47
// severity-bearing rows live in FOUR other containers plus the sibling finding queue:
//
//     32  findingQueue[]                        (intelligence_engine 27 + crypto_agent 5)
//      7  result.findings.<category>[]          (060 — a DICT, skipped by Array.isArray)
//      4  result.zeroTrust.<dim>.findings[]     (1023)
//      4  result.portResults[].issues[]         (040)
//      0  result.findings[]                     ← the only one it read
//
// ⚠️ THE ADAPTER IS CLASS P, NOT A RENAME. The queue's field names are NOT the ones
// `shapeFinding` assumes, measured on a real entry: `cves` is ABSENT (it is
// `evidence.cve[]`), `epss` is ABSENT (it is `epssScore`), `remediation` is an OBJECT
// (`{summary}`), and `port` is `target.port`. A reader that "just reads the queue" would
// render an empty CVE column, null every EPSS — falsifying the cover's own ordering
// promise — and print an object where remediation text belongs.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import { shapeHostFindings } from '../utils/report_inputs.mjs';
import { censusFindingContainers, READ_CONTAINERS, ALLOWLISTED_CONTAINERS } from '../utils/report_finding_census.mjs';

// ── Sanitised fixtures: REAL shapes, neutral values (CE is a public package) ──────

const QUEUE_ENTRY = {
  id: 'F-11111111-2222-3333-4444-555555555555',
  title: 'CVE-2020-25681 — dnsmasq 2.78',
  description: 'A heap-based buffer overflow in dnsmasq allows remote code execution.',
  severity: 'high',
  kev: false,
  epssScore: 0.81191,
  exploitPriority: 'ELEVATED',
  evidence: { cve: ['CVE-2020-25681'], source: 'intelligence_engine' },
  target: { host: '10.0.0.1', port: 53 },
  remediation: { summary: 'Update dnsmasq to a patched version.' },
};

const DNS_DICT_ENVELOPE = {            // 060 — findings is a DICT of categories
  id: '060',
  result: { up: true, findings: {
    cname: [],
    spf: [{ severity: 'high', check: 'missing_spf', detail: 'No SPF record found — domain is vulnerable to email spoofing' }],
    dmarc: [{ severity: 'high', check: 'missing_dmarc', detail: 'No DMARC record found' }],
  } },
};

const ZEROTRUST_ENVELOPE = {           // 1023
  id: '1023',
  result: { up: true, zeroTrust: {
    identity: { findings: [{ severity: 'medium', description: 'No MFA enforcement observed on the admin interface' }] },
  } },
};

const TLS_ENVELOPE = {                 // 040 — issues nested under each port result
  id: '040',
  result: { up: true, portResults: [
    { port: 443, severity: 'medium', issues: [{ severity: 'medium', check: 'weak_cipher', detail: 'CBC cipher suite offered' }] },
  ] },
};

const CLOUD_ENVELOPE = {               // the shape that already worked
  id: '1020',
  result: { up: true, findings: [{ bucket: 'b-example', severity: 'low', issues: ['Access logging not enabled – audit trail gap'] }] },
};

describe('the report reads every container a finding can live in', () => {
  // ── FOURTH QUADRANT FIRST ───────────────────────────────────────────────────

  it('a host with NO findings anywhere still reports none — that sentence must stay TRUE', () => {
    // "No findings were recorded in this run" is a real and necessary statement. The whole
    // repair is worthless if it becomes unreachable, because then a genuinely clean host
    // cannot be reported as clean.
    const out = shapeHostFindings('10.0.0.1', { results: [{ id: '003', result: { up: true } }] }, []);
    assert.deepEqual(out, []);
  });

  it('a CLOUD host renders exactly as before — the new readers must not disturb it', () => {
    const out = shapeHostFindings('aws', { results: [CLOUD_ENVELOPE] }, []);
    assert.equal(out.length, 1, 'exactly the one plugin finding, no duplicates from new readers');
    assert.match(out[0].title, /Access logging not enabled/);
  });

  it('a DICT of categories that are ALL empty contributes nothing', () => {
    const empty = { id: '060', result: { findings: { cname: [], spf: [], dmarc: [] } } };
    assert.deepEqual(shapeHostFindings('10.0.0.1', { results: [empty] }, []), []);
  });

  // ── THE DOORS THAT WERE SHUT ────────────────────────────────────────────────

  it('060 — a DICT of categories is read, one row per entry', () => {
    const out = shapeHostFindings('10.0.0.1', { results: [DNS_DICT_ENVELOPE] }, []);
    assert.equal(out.length, 2);
    assert.match(out.map((f) => f.title).join(' | '), /No SPF record found/);
    assert.match(out.map((f) => f.title).join(' | '), /No DMARC record found/);
  });

  it('1023 — zeroTrust.<dim>.findings[] is read', () => {
    const out = shapeHostFindings('10.0.0.1', { results: [ZEROTRUST_ENVELOPE] }, []);
    assert.equal(out.length, 1);
    assert.match(out[0].title, /No MFA enforcement/);
  });

  it('040 — portResults[].issues[] is read, and the port roll-up is NOT double-counted', () => {
    const out = shapeHostFindings('10.0.0.1', { results: [TLS_ENVELOPE] }, []);
    assert.equal(out.length, 1, 'the port result itself is a roll-up, not a second finding');
    assert.match(out[0].title, /CBC cipher suite offered/);
    assert.equal(out[0].port, 443, 'the issue inherits its port from the port result');
  });

  // ── THE QUEUE ADAPTER — every leg is a field the naive reader gets WRONG ──────

  it('the finding queue is read at all — this is the false clean itself', () => {
    const out = shapeHostFindings('10.0.0.1', { results: [] }, [QUEUE_ENTRY]);
    assert.equal(out.length, 1, 'a host whose only findings are in the queue must not read as clean');
    assert.match(out[0].title, /CVE-2020-25681/);
  });

  it('CVEs come from evidence.cve[] — `cves` is absent, so a naive reader shows an empty column', () => {
    const [f] = shapeHostFindings('10.0.0.1', { results: [] }, [QUEUE_ENTRY]);
    assert.deepEqual(f.cves, ['CVE-2020-25681']);
  });

  it('EPSS comes from epssScore — `epss` is absent, and the cover PROMISES EPSS ordering', () => {
    const [f] = shapeHostFindings('10.0.0.1', { results: [] }, [QUEUE_ENTRY]);
    assert.equal(f.epss, 0.81191,
      'a null EPSS here would make the report\'s own "ordered by EPSS probability" line false');
  });

  it('remediation is text, never the raw {summary} object', () => {
    const [f] = shapeHostFindings('10.0.0.1', { results: [] }, [QUEUE_ENTRY]);
    assert.equal(typeof f.remediation, 'string');
    assert.match(f.remediation, /Update dnsmasq/);
  });

  it('port comes from target.port, and the queue id is used verbatim', () => {
    const [f] = shapeHostFindings('10.0.0.1', { results: [] }, [QUEUE_ENTRY]);
    assert.equal(f.port, 53);
    assert.equal(f.id, QUEUE_ENTRY.id, 'the queue carries a STABLE id; prefer it over a content hash');
  });

  it('THREE findings whose titles truncate identically all survive — a hash collision is not a duplicate', () => {
    // Measured regression: plugin 1170 emits three separate 0.0.0.0/0 ingress findings for
    // one security group, and describeFinding truncates all three titles to the same 160
    // chars. A content-keyed dedup dropped two and took cloud CRITICAL from 10 to 8.
    const long = "Security Group 'sg-0def2fbb3db67eae5' (name='nsauditor-exposed-sg', vpc='vpc-0f82f090d58df59e0') allows unrestricted ingress from 0.0.0.0/0 to a restricted port";
    const env = { id: '1170', result: { findings: [
      { severity: 'critical', issues: [`${long} 22`] },
      { severity: 'critical', issues: [`${long} 3389`] },
      { severity: 'critical', issues: [`${long} 3306`] },
    ] } };
    assert.equal(shapeHostFindings('aws', { results: [env] }, []).length, 3);
  });

  // ── MERGE ───────────────────────────────────────────────────────────────────

  it('all five sources merge, de-duplicated by identical id ONLY', () => {
    // Never heuristic merging across producers: crypto_agent's TLS entries and 040's
    // per-check issues are different granularities of the same port, and BOTH belong in
    // the report with their own sources.
    const out = shapeHostFindings('10.0.0.1',
      { results: [DNS_DICT_ENVELOPE, ZEROTRUST_ENVELOPE, TLS_ENVELOPE, CLOUD_ENVELOPE] },
      [QUEUE_ENTRY, QUEUE_ENTRY]);
    assert.equal(out.length, 2 + 1 + 1 + 1 + 1,
      'two DNS + one zeroTrust + one TLS + one cloud + ONE queue entry (the duplicate id collapses)');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// THE CENSUS IS THE GUARD, AND IT IS WHAT ENDS THE LOOP.
//
// Five readers close five doors. The census answers the question nobody could answer
// before — "is there a finding we are NOT rendering?" — so the sixth door fails loudly
// instead of shipping as a clean report over a vulnerable host.
// ─────────────────────────────────────────────────────────────────────────────

describe('the container census fails loudly on a door nobody opened', () => {
  it('a record whose containers are all READ or ALLOWLISTED reports nothing unread', () => {
    const raw = { results: [DNS_DICT_ENVELOPE, ZEROTRUST_ENVELOPE, TLS_ENVELOPE, CLOUD_ENVELOPE] };
    assert.deepEqual(censusFindingContainers(raw, [QUEUE_ENTRY]).unread, {});
  });

  it('AN UNKNOWN CONTAINER IS REPORTED, NAMED — this is the whole point', () => {
    // The sixth door, simulated: a producer invents a new place to put findings.
    const raw = { results: [{ id: '999', result: { auditResults: [{ severity: 'high', detail: 'invented shape' }] } }] };
    const { unread } = censusFindingContainers(raw, []);
    assert.equal(Object.keys(unread).length, 1);
    assert.match(Object.keys(unread)[0], /UNCLASSIFIED:\.auditResults\[\]/,
      'the census must NAME the container, not bucket it into an anonymous "other"');
  });

  it('rendered rows reconcile with the censused findable count', () => {
    // The oracle: everything counted, minus the allowlisted roll-up, must come out as rows.
    const raw = { results: [DNS_DICT_ENVELOPE, ZEROTRUST_ENVELOPE, TLS_ENVELOPE, CLOUD_ENVELOPE] };
    const queue = [QUEUE_ENTRY];
    const { byContainer } = censusFindingContainers(raw, queue);
    const findable = Object.entries(byContainer)
      .filter(([k]) => !Object.prototype.hasOwnProperty.call(ALLOWLISTED_CONTAINERS, k))
      .reduce((a, [, n]) => a + n, 0);
    assert.equal(shapeHostFindings('10.0.0.1', raw, queue).length, findable);
  });

  it('every allowlist entry carries a written reason — an empty one closes a door by accident', () => {
    for (const [k, why] of Object.entries(ALLOWLISTED_CONTAINERS)) {
      assert.ok(typeof why === 'string' && why.trim().length > 40,
        `allowlist entry "${k}" needs a real reason, not a placeholder`);
    }
  });

  it('READ_CONTAINERS and ALLOWLISTED_CONTAINERS are disjoint', () => {
    // A key in both would make the census unfalsifiable for that container: it would pass
    // whether or not the reader still existed.
    for (const k of READ_CONTAINERS) {
      assert.equal(Object.prototype.hasOwnProperty.call(ALLOWLISTED_CONTAINERS, k), false,
        `"${k}" is both read and allowlisted — the allowlist would mask a deleted reader`);
    }
  });
});
