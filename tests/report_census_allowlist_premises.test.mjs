// tests/report_census_allowlist_premises.test.mjs
//
// AN ALLOWLIST ENTRY THAT OUTLIVES THE FACT JUSTIFYING IT IS A FALSE CLEAN.
//
// `ALLOWLISTED_CONTAINERS` excuses a container from the finding census — "these
// severity-bearing objects are not lost findings, and here is why". Two of the four reasons
// asserted a FACT about a particular run rather than a property of the shape, and the
// cisAlarmCoverage entry said so in its own prose: "If that ever stops holding the mirror
// has broken and this entry is wrong — re-derive, do not re-assert." NOTHING RE-DERIVED IT.
// A carve-out whose premise has silently become false excludes real findings from a client
// deliverable while the census still reports `unread: {}` — the census's own exit code
// wearing a measurement it never made.
//
// So each entry now carries a `verify(raw, queue)` beside its reason, and a premise that
// FAILS or THROWS withdraws the carve-out: the container is counted UNREAD and the operator
// is told WHY it is unread, because "nobody wrote a reader" and "the reason we wrote no
// reader stopped being true" are different facts and the remediation differs.
//
// ⚠️ THE LEG THAT WILL ROT IS THE ACCEPT LEG, so it is written first. Every fixture born
// from an incident satisfies the accept case by construction, which is how a positive scope
// silently becomes decoration; and here the accept case is load-bearing in its own right —
// four verifiers that go red on healthy data would train an operator to read past the one
// warning this whole census exists to raise.

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';

import {
  censusFindingContainers,
  resolveUnreadCount,
  adjudicateAllowlistEntry,
  ALLOWLISTED_CONTAINERS,
} from '../utils/report_finding_census.mjs';

// ── Fixtures: REAL shapes, neutral values ────────────────────────────────────
//
// Every shape below was derived from the real records under audit-evidence-samples/ (152
// scan_conclusion_raw.json files, cloud and network), not invented: 1040's uncovered entry
// is {id,title,severity,coverageMode} and its paired finding carries `details.cisId` plus an
// "alarm missing" issue string; 1030's policyAnalyses issues are OBJECTS ({severity,detail,
// statement}) while the parent's own issues are STRINGS; 1150/1170 emit data[] rows that are
// deep-equal to their findings[] rows; a network host's data[] rows carry probe telemetry and
// NO severity at all.

const cisEnvelope = ({ uncovered, paired }) => ({
  id: '1040',
  name: 'AWS CloudTrail + CloudWatch Operational Integrity',
  result: {
    up: true,
    summary: {
      cisAlarmCoverage: {
        evaluated: true, covered: 0, total: uncovered.length, truncated: false,
        uncovered: uncovered.map((id) => ({
          id, title: `Alarm class ${id}`, severity: 'medium', coverageMode: 'any-hint',
        })),
      },
    },
    findings: paired.map((id) => ({
      resource: 'cloudwatch:alarm-coverage',
      severity: 'medium',
      issues: [`CloudWatch alarm missing: Alarm class ${id} (CIS AWS Foundations Benchmark ${id}). `
        + 'SOC 2 CC7.2 expects active monitoring for this event class.'],
      details: { cisId: id, category: 'cis-alarm-coverage-no-filter', evidenceMethod: 'metric-filter-pattern-v2' },
    })),
  },
});

const iamEnvelope = (ownIssues) => ({
  id: '1030',
  name: 'AWS IAM Auditor',
  result: {
    up: true,
    findings: [{
      userName: 'user-example',
      severity: 'critical',
      issues: ownIssues,
      policyAnalyses: [{
        policyName: 'policy-example', policyArn: null, source: 'user-inline', hasFullAdmin: true,
        issues: [{
          severity: 'critical',
          detail: 'Full admin grant: Action "*" in policy "policy-example"',
          statement: { Effect: 'Allow', Action: '*', Resource: '*' },
        }],
      }],
    }],
  },
});

const MIRRORED_ROW = {
  severity: 'medium',
  issues: ["SQS queue 'q-example' has NO CloudWatch MetricAlarm on AWS/SQS:ApproximateAgeOfOldestMessage."],
  details: { control: 'CC7.2' },
  region: 'us-east-1',
  resource: 'q-example',
};

const cloudDataEnvelope = ({ data, findings }) => ({
  id: '1150', name: 'AWS SQS/SNS Auditor', result: { up: true, data, findings },
});

const tlsEnvelope = (portResults) => ({
  id: '040', name: 'TLS Certificate & Cipher Auditor', result: { up: true, portResults },
});

const HEALTHY_TLS = [{
  port: 443, service: 'https', up: true, severity: 'medium',
  issues: [{ severity: 'medium', check: 'weak_cipher', detail: 'CBC cipher suite offered' }],
}];

/** A record in which EVERY allowlisted container is present and EVERY premise holds. */
const healthyRecord = () => ({
  results: [
    cisEnvelope({ uncovered: ['cis-3.1', 'cis-3.2'], paired: ['cis-3.1', 'cis-3.2'] }),
    iamEnvelope(['SHADOW ADMIN: User has full wildcard (*) permissions']),
    cloudDataEnvelope({ data: [MIRRORED_ROW], findings: [MIRRORED_ROW] }),
    tlsEnvelope(HEALTHY_TLS),
  ],
});

const ALLOWLISTED_KEYS = [
  'result.portResults[]',
  'result.summary.cisAlarmCoverage.uncovered[]',
  'result.findings[].policyAnalyses[].issues[]',
  'result.data[]',
];

/** The discrimination oracle: exactly ONE premise broke, and it is the named one. */
function assertOnlyFailure(census, key) {
  assert.deepEqual(Object.keys(census.premiseFailures), [key],
    `exactly one premise must break — a fixture that trips two verifiers proves neither. `
    + `Got: ${JSON.stringify(census.premiseFailures)}`);
  assert.deepEqual(Object.keys(census.unread), [key],
    'a failed premise withdraws its OWN carve-out and no other');
  for (const other of ALLOWLISTED_KEYS.filter((k) => k !== key)) {
    assert.equal(Object.prototype.hasOwnProperty.call(census.unread, other), false,
      `"${other}" must still be carved out — its premise was not the one broken`);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// FOURTH QUADRANT FIRST — healthy data must stay silent.
// ─────────────────────────────────────────────────────────────────────────────

describe('the accept leg: a record whose premises all hold is carved out silently', () => {
  it('every allowlisted container present, every premise TRUE — no unread, no premise failures', () => {
    const c = censusFindingContainers(healthyRecord(), []);
    assert.deepEqual(c.premiseFailures, {},
      'four verifiers over healthy data must produce nothing — a verifier that cries wolf on a '
      + 'normal run is how an operator learns to read past the one warning that matters');
    assert.deepEqual(c.unread, {});
    // The census still SEES them; it is the carve-out, not the count, that the premise governs.
    for (const k of ALLOWLISTED_KEYS) {
      assert.ok(c.byContainer[k] > 0, `${k} must be counted, carve-out or not`);
    }
  });

  it('a CLEAN TLS port — severity "pass" over an EMPTY issues[] — is accepted', () => {
    // 040 seeds its roll-up at SEVERITY.PASS and raises it to the max of the port's own
    // issues (plugins/040_tls_cert_auditor.mjs:491-496), so a port with nothing wrong emits
    // exactly {severity:'pass', issues:[]}. That is the identity element of the roll-up, not
    // a finding nobody rendered, and failing it would red-flag every clean HTTPS port.
    const c = censusFindingContainers(
      { results: [tlsEnvelope([{ port: 443, service: 'https', up: true, severity: 'pass', issues: [] }])] }, []);
    assert.deepEqual(c.premiseFailures, {});
    assert.deepEqual(c.unread, {});
  });

  it('the NETWORK shape — findings[] empty, data[] full of probe telemetry — is accepted', () => {
    // Measured on the real 192.168.1.1 run: findings[]=0 and data[]=85, of which 84 are
    // {probe_protocol, probe_port, probe_info}. None carries a `severity`, so none is in the
    // census's subject and there is nothing for the mirror premise to mirror. The acceptance
    // is STRUCTURAL, not an exemption keyed on telemetry field names.
    const telemetry = Array.from({ length: 85 }, (_, i) => ({
      probe_protocol: i % 2 ? 'tcp' : 'udp', probe_port: 1000 + i, probe_info: 'Connect refused (ECONNREFUSED)',
    }));
    const c = censusFindingContainers({ results: [{ id: '020', result: { up: true, findings: [], data: telemetry } }] }, []);
    assert.deepEqual(c.premiseFailures, {});
    assert.deepEqual(c.unread, {});
    assert.equal(c.byContainer['result.data[]'], undefined,
      'telemetry with no severity is not a census subject at all');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// THE REJECT LEGS — one discriminating fixture per verifier.
// ─────────────────────────────────────────────────────────────────────────────

describe('a broken premise withdraws its own carve-out', () => {
  it('(i) an uncovered CIS class with NO paired "alarm missing" finding', () => {
    // The exact state the entry's own prose said to re-derive: the 1:1 mirror stops being
    // 1:1. cis-3.3 is then an alarm gap that reaches no reader.
    const raw = { results: [
      cisEnvelope({ uncovered: ['cis-3.1', 'cis-3.2', 'cis-3.3'], paired: ['cis-3.1', 'cis-3.2'] }),
      iamEnvelope(['SHADOW ADMIN: User has full wildcard (*) permissions']),
      cloudDataEnvelope({ data: [MIRRORED_ROW], findings: [MIRRORED_ROW] }),
      tlsEnvelope(HEALTHY_TLS),
    ] };
    const c = censusFindingContainers(raw, []);
    assertOnlyFailure(c, 'result.summary.cisAlarmCoverage.uncovered[]');
    assert.match(c.premiseFailures['result.summary.cisAlarmCoverage.uncovered[]'], /cis-3\.3/,
      'the detail must NAME the class that lost its mirror — "the premise failed" is not actionable');
    assert.doesNotMatch(c.premiseFailures['result.summary.cisAlarmCoverage.uncovered[]'], /cis-3\.1/,
      'and must not smear the two classes that DID pair');
  });

  it('(i) a paired finding whose cisId belongs to a NON-alarm category does not count as the mirror', () => {
    // The details channel is scoped to alarm-coverage findings on purpose: a cisId attached
    // to some unrelated finding is not evidence that the alarm gap was rendered.
    const env = cisEnvelope({ uncovered: ['cis-3.1'], paired: [] });
    env.result.findings = [{
      resource: 'iam:root', severity: 'high', issues: ['Root account has an active access key'],
      details: { cisId: 'cis-3.1', category: 'iam-root-access-key' },
    }];
    const c = censusFindingContainers({ results: [env] }, []);
    assert.deepEqual(Object.keys(c.premiseFailures), ['result.summary.cisAlarmCoverage.uncovered[]']);
  });

  it('(ii) a parent finding with policy-analysis issues and NO issue of its own', () => {
    // shapeFinding titles a finding from its own issues[]/detail/description; with none it
    // renders "(untitled finding)" (utils/report_inputs.mjs:139-151). So the parent is an
    // empty row and its seven statement-level issues reach nobody — the nested detail is
    // then the ONLY evidence, which is precisely what the carve-out denies.
    const raw = { results: [
      cisEnvelope({ uncovered: ['cis-3.1'], paired: ['cis-3.1'] }),
      iamEnvelope([]),
      cloudDataEnvelope({ data: [MIRRORED_ROW], findings: [MIRRORED_ROW] }),
      tlsEnvelope(HEALTHY_TLS),
    ] };
    const c = censusFindingContainers(raw, []);
    assertOnlyFailure(c, 'result.findings[].policyAnalyses[].issues[]');
    assert.match(c.premiseFailures['result.findings[].policyAnalyses[].issues[]'], /findings\[0\]/,
      'the detail must locate the parent');
  });

  it('(ii) an issues[] holding only blank strings is not an issue of its own', () => {
    const c = censusFindingContainers({ results: [iamEnvelope(['   '])] }, []);
    assert.deepEqual(Object.keys(c.premiseFailures), ['result.findings[].policyAnalyses[].issues[]'],
      'a whitespace issue renders as no text at all — presence is not content');
  });

  it('(iii) a severity-bearing data[] row that is NOT mirrored in findings[]', () => {
    const orphan = { ...MIRRORED_ROW, resource: 'q-orphan', severity: 'high' };
    const raw = { results: [
      cisEnvelope({ uncovered: ['cis-3.1'], paired: ['cis-3.1'] }),
      iamEnvelope(['SHADOW ADMIN: User has full wildcard (*) permissions']),
      cloudDataEnvelope({ data: [MIRRORED_ROW, orphan], findings: [MIRRORED_ROW] }),
      tlsEnvelope(HEALTHY_TLS),
    ] };
    const c = censusFindingContainers(raw, []);
    assertOnlyFailure(c, 'result.data[]');
    assert.match(c.premiseFailures['result.data[]'], /q-orphan|1150/,
      'the detail must locate the unmirrored row');
  });

  it('(iii) the mirror is scoped to ONE plugin result — a lookalike next door does not vouch for it', () => {
    // The comment says "content-equal finding in the same plugin result", and a declared
    // limit has to be true about the code. Matching across results would let any producer's
    // row be excused by a coincidentally identical row emitted by a different plugin.
    const c = censusFindingContainers({ results: [
      cloudDataEnvelope({ data: [MIRRORED_ROW], findings: [] }),
      { id: '1170', name: 'AWS EC2 SG Perimeter Auditor', result: { up: true, findings: [MIRRORED_ROW] } },
    ] }, []);
    assert.deepEqual(Object.keys(c.premiseFailures), ['result.data[]']);
  });

  it('(iii) a telemetry row that GAINS a severity stops being telemetry and must fail', () => {
    // The inverse of the network accept leg above, and the reason that leg is structural
    // rather than an exemption: the moment a probe row carries a severity it is a
    // severity-bearing object in a container nobody reads.
    const c = censusFindingContainers({ results: [{ id: '020', result: {
      up: true, findings: [], data: [{ probe_protocol: 'tcp', probe_port: 22, probe_info: 'open', severity: 'high' }],
    } }] }, []);
    assert.deepEqual(Object.keys(c.premiseFailures), ['result.data[]']);
    assert.equal(c.unread['result.data[]'], 1);
  });

  it('(iv) a port roll-up with a severity over an EMPTY issues[] is a finding nothing renders', () => {
    const raw = { results: [
      cisEnvelope({ uncovered: ['cis-3.1'], paired: ['cis-3.1'] }),
      iamEnvelope(['SHADOW ADMIN: User has full wildcard (*) permissions']),
      cloudDataEnvelope({ data: [MIRRORED_ROW], findings: [MIRRORED_ROW] }),
      tlsEnvelope([{ port: 8443, service: 'https-alt', up: true, severity: 'high', issues: [] }]),
    ] };
    const c = censusFindingContainers(raw, []);
    assertOnlyFailure(c, 'result.portResults[]');
    assert.match(c.premiseFailures['result.portResults[]'], /8443/, 'the detail must name the port');
  });

  it('(iv) a roll-up severity ABSENT from its own issue severities summarises something it does not hold', () => {
    const c = censusFindingContainers({ results: [tlsEnvelope([{
      port: 443, severity: 'critical',
      issues: [{ severity: 'medium', check: 'weak_cipher', detail: 'CBC cipher suite offered' }],
    }])] }, []);
    assert.deepEqual(Object.keys(c.premiseFailures), ['result.portResults[]']);
    assert.match(c.premiseFailures['result.portResults[]'], /critical/);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// THE PREMISE MACHINERY — fail CLOSED, and stay DISTINGUISHABLE from "unknown".
// ─────────────────────────────────────────────────────────────────────────────

describe('a premise that cannot answer has not established anything', () => {
  it('a verifier that THROWS counts as a FAILED premise, never as a pass', () => {
    const boom = { reason: 'x'.repeat(60), verify: () => { throw new TypeError('cannot read properties of undefined'); } };
    const v = adjudicateAllowlistEntry(boom, {}, []);
    assert.notEqual(v, null, 'a throw must not fall through to "the carve-out stands"');
    // ⚠️ `adjudicateAllowlistEntry` returns `{detail, unreadCount}` since the false-quantity
    // repair — a failure now carries HOW MANY objects it leaves unread, not just a sentence.
    // The count is validated by `resolveUnreadCount`, never trusted from the verifier.
    assert.equal(typeof v, 'object', 'a failure is a verdict object, not a bare string');
    assert.match(v.detail, /THREW|cannot read properties/);
    assert.equal(v.unreadCount, undefined,
      'a THROW cannot quantify anything — it must carry no count, so the caller degrades to the '
      + 'full population rather than inventing a number');
  });

  it('a verifier returning something that is not a verdict FAILS CLOSED', () => {
    for (const bad of [undefined, null, true, 'ok', {}, { ok: 'yes' }]) {
      const v = adjudicateAllowlistEntry({ reason: 'x'.repeat(60), verify: () => bad }, {}, []);
      assert.notEqual(v, null, `a verify() returning ${JSON.stringify(bad)} must not read as a pass`);
    }
  });

  it('an entry with NO verifier keeps its carve-out — verify is optional by design', () => {
    // The fourth quadrant of the machinery itself. An undeclared premise is not a failed
    // one; the ratchet below is what stops "undeclared" becoming the default.
    assert.equal(adjudicateAllowlistEntry({ reason: 'x'.repeat(60) }, {}, []), null);
  });

  it('a verifier receives the queue as its second argument', () => {
    let seen = null;
    adjudicateAllowlistEntry({ reason: 'x'.repeat(60), verify: (raw, queue) => { seen = queue; return { ok: true }; } },
      {}, [{ id: 'q1' }]);
    assert.deepEqual(seen, [{ id: 'q1' }]);
  });

  it('a FAILED PREMISE and an UNKNOWN CONTAINER are both unread, and they are told apart', () => {
    // Both produce "this report does not read it", and the remediation is opposite: one
    // needs a reader written, the other needs a carve-out re-argued or withdrawn.
    const raw = { results: [
      cisEnvelope({ uncovered: ['cis-3.1', 'cis-3.9'], paired: ['cis-3.1'] }),
      { id: '999', result: { auditResults: [{ severity: 'high', detail: 'a sixth door' }] } },
    ] };
    const c = censusFindingContainers(raw, []);
    assert.deepEqual(Object.keys(c.unread).sort(),
      ['UNCLASSIFIED:.auditResults[]', 'result.summary.cisAlarmCoverage.uncovered[]']);
    assert.deepEqual(Object.keys(c.premiseFailures), ['result.summary.cisAlarmCoverage.uncovered[]'],
      'an unknown container has no premise to fail — it was never justified in the first place');
  });
});

describe('the return shape stays backward compatible', () => {
  it('byContainer / unread / total survive a premise failure, and total is unchanged by it', () => {
    // utils/report_inputs.mjs:386 and cli.mjs:1374 read this object; a premise failure must
    // change the VERDICT, never the arithmetic.
    const ok = censusFindingContainers(healthyRecord(), []);
    const broken = censusFindingContainers({ results: [
      cisEnvelope({ uncovered: ['cis-3.1', 'cis-3.2'], paired: [] }),
      iamEnvelope(['SHADOW ADMIN: User has full wildcard (*) permissions']),
      cloudDataEnvelope({ data: [MIRRORED_ROW], findings: [MIRRORED_ROW] }),
      tlsEnvelope(HEALTHY_TLS),
    ] }, []);
    for (const c of [ok, broken]) {
      assert.equal(typeof c.byContainer, 'object');
      assert.equal(typeof c.unread, 'object');
      assert.equal(typeof c.total, 'number');
      assert.equal(c.total, Object.values(c.byContainer).reduce((a, b) => a + b, 0));
    }
    assert.equal(broken.byContainer['result.summary.cisAlarmCoverage.uncovered[]'], 2,
      'the count is what the walk saw; the carve-out is a separate question');
    assert.equal(broken.unread['result.summary.cisAlarmCoverage.uncovered[]'], 2,
      'and the unread count is that same number, not a flag');
  });

  it('the queue still lands in byContainer and never triggers a premise', () => {
    const c = censusFindingContainers({ results: [] }, [{ id: 'F-1', severity: 'high' }]);
    assert.equal(c.byContainer['findingQueue[]'], 1);
    assert.deepEqual(c.premiseFailures, {});
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// THE RATCHET. A carve-out with nothing re-deriving it is the defect this file closes;
// counting them is what stops the next one being added silently.
// ─────────────────────────────────────────────────────────────────────────────

describe('the allowlist SHAPE is enforced, not conventional', () => {
  it('every entry is {reason, verify} — a bare string reason is the OLD shape and must not return', () => {
    for (const [k, entry] of Object.entries(ALLOWLISTED_CONTAINERS)) {
      assert.equal(typeof entry, 'object', `"${k}" must be an object, not a bare reason string`);
      assert.ok(typeof entry.reason === 'string' && entry.reason.trim().length > 40,
        `"${k}" needs a real written reason, not a placeholder`);
    }
  });

  it('all four entries carry a verifier — adding a fifth without one is a deliberate act', () => {
    // Not "verify is required": the module tolerates an entry that declares no premise,
    // because a shape nobody can check yet is better carved out loudly than checked wrongly.
    // This leg is the RATCHET — it fails on a new unverified entry so the choice is argued
    // in a review rather than defaulted into.
    const without = Object.entries(ALLOWLISTED_CONTAINERS)
      .filter(([, e]) => typeof e.verify !== 'function').map(([k]) => k);
    assert.deepEqual(without, [],
      'these carve-outs assert a fact nothing re-derives — give each a verify(raw, queue) or '
      + 'record here, with a measurement, why its premise is not checkable');
  });
});

describe('a BROKEN premise reports the BREAK, not the container', () => {
  /**
   * ⚠️ THE REPAIR FOR ONE FALSE CLEAN INTRODUCED A FALSE QUANTITY IN THE CLIENT DELIVERABLE, and
   * two independent review lenses found it before it shipped.
   *
   * `censusFindingContainers` wrote `unread[k] = n`, where `n` is the container's WHOLE
   * severity-object count, and `utils/executive_report.mjs` renders that number as
   *   "⚠️ N recorded finding-like object(s) live in containers this report does not read,
   *    and are NOT included above — … Treat this report as incomplete for those surfaces."
   * For a MIRROR carve-out that breaks PARTIALLY, most of those objects ARE rendered above. Real
   * trigger, not hypothetical: plugin 1150 emits `data: findings`, so a run with 16 mirrored rows
   * and ONE orphan told the client that 17 objects were missing from a report containing 16 of
   * them — **a caveat contradicting the body of its own document**, in the direction that alarms
   * a customer, and `cli.mjs` prints the same figure to the operator.
   *
   * Same family as the `findings ?? data` fallback the 0.44.0 cycle reverted: a repair to a false
   * clean flooding a consumer that was only correct because the defect was starving it.
   *
   * ⚠️ AND THE VALIDATION MATTERS MORE THAN THE FIELD. `unreadCount ?? n` alone catches only
   * `null`/`undefined`, so a verifier returning `0` on a real break, or `"3"`, or a count ABOVE
   * the population, would pass a garbage number straight into a client-facing sentence. The rule
   * is: accept a non-negative integer ≤ the population, else fall back to the population.
   * **Degrade to OVER-reporting, never to a silent or impossible number** — a guard against a
   * false quantity that can itself emit one is no guard.
   */
  const orphanRecord = (mirrored, orphans) => ({
    results: [{
      id: '1150',
      result: {
        up: true,
        findings: mirrored.map((i) => ({ resource: `q${i}`, severity: 'high', issues: [`Queue ${i} is public`] })),
        data: [
          ...mirrored.map((i) => ({ resource: `q${i}`, severity: 'high', issues: [`Queue ${i} is public`] })),
          ...orphans.map((i) => ({ resource: `orphan${i}`, severity: 'high', issues: [`Orphan ${i}`] })),
        ],
      },
    }],
  });

  // FOURTH QUADRANT FIRST: an INTACT mirror must still carve out cleanly. Every fixture below is
  // born from the break; none of them proves the accept path survives the fix.
  it('an intact mirror is still carved out — no unread, no premise failure', () => {
    const { unread, premiseFailures } = censusFindingContainers(orphanRecord([1, 2, 3], []), []);
    assert.deepEqual(unread, {}, 'an intact mirror was reported as unread');
    assert.deepEqual(premiseFailures, {}, 'an intact mirror reported a premise failure');
  });

  it('a PARTIAL break reports the ORPHANS, not the whole container', () => {
    const raw = orphanRecord([1, 2, 3], [9]);
    const { byContainer, unread } = censusFindingContainers(raw, []);
    assert.equal(byContainer['result.data[]'], 4, 'the population belongs in byContainer');
    assert.equal(unread['result.data[]'], 1,
      'the client is told the CONTAINER count, so a report rendering 3 of 4 objects claims 4 are '
      + `missing. Got ${unread['result.data[]']}, expected the 1 unmirrored row.`);
  });

  it('resolveUnreadCount: a failure that does NOT quantify falls back to the FULL population', () => {
    // ⚠️ TESTED THROUGH THE EXPORTED PURE FUNCTION, not through a test-only seam in the census.
    // The first draft of this leg passed an `__overrideAllowlist` option into production code to
    // reach the degradation paths — a test hook in a shipped module, and it passed VACUOUSLY
    // because the option did not exist yet and the assertion happened to match the old behaviour.
    // The logic under test is a pure decision about a number; it is exported and driven directly.
    assert.equal(resolveUnreadCount({ ok: false, detail: 'broken, no count' }, 4), 4,
      'an unquantified failure must report the whole container, not 0 and not undefined');
  });

  it('resolveUnreadCount: an out-of-range or non-integer count degrades to the population', () => {
    for (const bad of [-1, 0.5, 99, '3', NaN, null, undefined, true, [], {}]) {
      assert.equal(resolveUnreadCount({ ok: false, detail: 'd', unreadCount: bad }, 4), 4,
        `unreadCount ${String(bad)} must be refused and degrade to the population, not trusted`);
    }
    // …and a VALID count is honoured, or the rule above is satisfied by ignoring the field.
    assert.equal(resolveUnreadCount({ ok: false, detail: 'd', unreadCount: 2 }, 4), 2,
      'a valid unreadCount was ignored — the guard would then be unable to report a partial break');
    // ZERO is valid arithmetic and a CONTRADICTION here: a failure claiming nothing is unread is
    // a verifier bug, and trusting it would silence the very break it just reported.
    assert.equal(resolveUnreadCount({ ok: false, detail: 'd', unreadCount: 0 }, 4), 4,
      'a failure claiming ZERO unread objects must not silence itself');
  });
});
