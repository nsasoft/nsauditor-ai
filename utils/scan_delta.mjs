// Cross-run delta — "what changed since the last scan" (Pro/Enterprise).
//
// ⚠️ NOT `utils/delta_reporter.mjs`. That is the FREE CE last-vs-current alerting delta on the
// webhook path and it stays free, untouched and un-gated. This is a second engine, over two
// ARBITRARY run records, at FINDING level.
//
// ⚠️ THE WHOLE DESIGN IS THE REFUSAL, because "RESOLVED" IS THE DANGEROUS VERDICT. A finding
// that disappeared for any reason other than being fixed reads to a buyer, and to an assessor,
// as remediation. Five ways a finding can vanish without being fixed, every one observed in this
// product's own history:
//   1. HOST      — the host was not scanned in the current run.
//   2. PLUGIN    — the plugin that produced it did not run (`--plugins` differed).
//   3. SCOPE     — an evidence gap: AccessDenied, budget exceeded, incomplete region enumeration.
//                  A FINDING THAT DISAPPEARED BECAUSE THE SCANNER LOST PERMISSION IS NOT FIXED.
//   4. FRAMEWORK — the control enumeration moved (PCI went 19/9/39 → 19/9/44 in one cycle), so a
//                  control that "appeared" or "left" is an enumeration change, not a posture change.
//   5. PRODUCT   — the §5.3 semantics boundary, below. This one is written in our own contract.
// A finding may be called RESOLVED only when its host, plugin, scope and framework enumeration
// were in scope in BOTH runs. Otherwise it goes to NOT-COMPARABLE **with its reason** — never
// into `resolved`, and never silently dropped.
// ⚠️ 1.2.0 limit, boarded for 1.2.1: "plugin" is a PLUGIN row's own producer. An analysis agent's or the
// CVE mapper's row is derived from other plugins' output, and whether those were requested in both runs
// is NOT checked — narrow `--plugins` in one run and such a row goes into `resolved` (or `new`).
// AGENT_SCOPE_FROM_TIER discloses it; tests/build6_delta_scope_honesty.test.mjs pins it until the check exists.
// Integrity is a fact about BYTES ON DISK, so the caller measures it with `utils/run_chain.mjs`
// and passes the verdict in. Keeping it out of this module means the comparability rules can be
// driven without a filesystem, and the chain can be driven without the delta.
export const SCAN_DELTA_SCHEMA = 1;

// ⚠️ REASON CODES ARE APPEND-ONLY UNDER `SCAN_DELTA_SCHEMA = 1`. Adding one is additive and needs
// no schema bump; RENAMING or REMOVING one changes what an existing consumer's stored verdicts
// mean, and bumps the schema.
//
// ⚠️ AND THEY ARE DECLARED HERE BECAUSE TWO SURFACES ARE WRITTEN FROM THEM RATHER THAN FROM A
// COUNT SOMEBODY DID BY HAND. The CE CHANGELOG's "N ways a finding can vanish without being
// fixed" sentence and the agent-skill's item (2) have both already shipped a count that disagreed
// with the code — a count with no list beside it is invisible to every gate this product owns.
// `tests/scan_delta.test.mjs` holds these in EQUALITY with the codes derived from this file's own
// source: a new code that forgets the declaration fails, and so does a declaration whose code is
// gone. The ORDER is the order the engine evaluates them, which is the order a reader meets them.
//
// ⚠️ CE 0.2.55 IS THE FIRST TARBALL THAT SHIPS THIS FILE, SO IT IS THE LAST RELEASE IN WHICH A
// CODE HERE CAN BE RENAMED FOR FREE. Measured, both directions: `npm pack nsauditor-ai@0.2.54`
// contains 87 entries, 47 under `utils/`, and NO `utils/scan_delta.mjs` (positive control:
// `utils/report_inputs.mjs` is present); `npm pack --dry-run` at this version contains 92 entries
// INCLUDING `scan_delta.mjs`, `scan_delta_view.mjs` and `executive_report.mjs`. That is why
// `plugin-identity-basis-changed` could be renamed to `identity-basis-changed` this cycle rather
// than papered over with a display label — zero published verdicts carried it. From the next
// release on, a consumer can hold stored verdicts keyed on these strings, and a rename becomes a
// schema change that must be versioned rather than an edit. Check the claim before relying on
// either half of it: the question is what the PUBLISHED TARBALL contains, never what git says.
// ⚠️ ONE NAME, TWO CONSUMERS. The delta refuses a straddling row with this reason, and Enterprise's
// MTTR engine withholds the same row's CLOSURE with the same reason (EE build 5, F1(b)) — the two
// must not disagree about what counts as the same finding, so the second one IMPORTS the value
// rather than typing it. Same value as before, so no stored verdict changes meaning.
export const IDENTITY_BASIS_CHANGED_REASON = 'identity-basis-changed';
// The same rule for the two PLUGIN-scope reasons: Enterprise's MTTR engine withholds a prior row's
// closure when its plugin did not run (or ran and was not measured) in the current scan — the
// delta's own two verdicts — so it imports these names rather than typing the strings. Values
// unchanged, so no stored verdict changes meaning.
export const PLUGIN_NOT_RUN_REASON = 'plugin-not-run';
export const PLUGIN_NOT_MEASURED_REASON = 'plugin-not-measured';
// And the COVERAGE reason: Enterprise's MTTR engine refuses to call a prior regional row remediated
// when its region lay outside the current scan's recorded scope — the delta's own verdict, same name.
export const SCOPE_NOT_SCANNED_REASON = 'scope-not-scanned';
// And the PORT reason (EE 1.1.0 build 9, F6). A probe RAN on a port the port scanner saw open and did not
// complete its connection there (a reset, a timeout, a handshake that never finished), so that port was
// not measured in the run. Enterprise records it as a service-set INPUT GAP carrying the port. A baseline
// row on that port that is absent now was not fixed — nobody looked. Measured on a live acceptance run:
// the router's 443 answered the port scanner and then reset the HTTPS probe; crypto_agent's row about 443
// could not be produced, and this engine reported it RESOLVED. Enterprise's MTTR engine applies the same
// reason to a prior row's CLOSURE and imports both names from here, so the two channels cannot disagree.
export const PROBE_NOT_MEASURED_REASON = 'probe-not-measured';
// And the port that STOPPED ANSWERING (EE 1.1.0 build 12). The port scanner saw it OPEN in the run that holds
// the finding, and in the other run it RAN and recorded the port neither open nor closed — no answer inside its
// timeout (filtered), or not probed at all. Nothing was measured there, so a row on that port neither vanished nor
// appeared. Measured on Gate 2 of build 11: the gateway filtered 21 and 80 for three minutes, and three findings on
// those ports read RESOLVED in the client's delta; five minutes later both ports were open again. A port in the
// other run's tcpClosed WAS measured, and RESOLVED there stays legitimate. Enterprise's MTTR imports this name.
export const PORT_NOT_MEASURED_REASON = 'port-not-measured';
// A UDP-TRANSPORT FINDING THAT VANISHED WAS NOT MEASURED AS FIXED EITHER (1.1.1 board — found by the 1.1.0 web
// cascade's reviewer driving the shipped engine). The TCP rule above keys on the port NUMBER in the holding run's
// tcpOpen, so an SNMP 161/udp row that disappeared read RESOLVED with no caveat anywhere, and a udp/53 DNS row was
// judged by TCP/53's state. No shipped UDP producer records a positive negative — SNMP records `no response`, DNS a
// timeout, and the port scanner's `udpClosed` is empty on every sealed raw measured — so UDP SILENCE IS
// INDISTINGUISHABLE FROM FILTERED, and a UDP row in one run only is NOT COMPARABLE unless the other run's service set
// shows the port MEASURED for that producer (`udpPortMeasurement`: closed, or answered — and, for the CVE mapper,
// identified). Same token, its own detail. What decides "UDP" is the finding's `protocol`, which is an APPLICATION LABEL, not a transport (the
// concluder takes it from `probe_protocol || result.protocol || 'tcp'`), so the decision is this table.
//
// ⚠️ THE TABLE IS DERIVED, NOT HAND-LISTED: its keys are held in equality with every protocol label the shipped
// producers WRITE — CE's plugins and utils here (`tests/udp_transport_label_census.test.mjs`), and Enterprise's
// plugins, agents and engine on its side — so a label outside it is unreachable through the shipped path, and the
// runtime default for an unknown label (not UDP, today's verdict) is a default nothing exercises. `dns` is classed
// UDP because that is the SAFE direction, and its cost is STATED: a TCP-53 row labelled `dns` — a zone transfer (AXFR)
// finding, which is TCP — OVER-REFUSES (it reads not-comparable where a closed TCP/53 would have been a measured fix),
// while a UDP DNS row labelled TCP would read RESOLVED on a closed TCP/53. 060 writes port-53 rows under both `udp`
// and `dns`, so the choice is live, not theoretical. `other` is a label with no port-bearing transport (ICMP, ARP, the
// concluder's meta labels, which it filters out of the service set before any producer reads them).
export const TRANSPORT_OF_LABEL = Object.freeze({
  udp: 'udp', mdns: 'udp', dnssd: 'udp', llmnr: 'udp', upnp: 'udp', dns: 'udp',
  tcp: 'tcp', 'tcp-ack': 'tcp', http: 'tcp', https: 'tcp', tr069: 'tcp',
  icmp: 'other', 'icmp-timestamp': 'other', arp: 'other', 'os-detector': 'other', assessment: 'other', api: 'other',
});
export const UDP_TRANSPORT_LABELS = Object.freeze(Object.keys(TRANSPORT_OF_LABEL).filter((l) => TRANSPORT_OF_LABEL[l] === 'udp'));
/** Is this protocol label a UDP transport? Case-insensitive; anything not a string, or not in the table, is not. */
export const isUdpTransport = (label) => typeof label === 'string' && TRANSPORT_OF_LABEL[label.toLowerCase()] === 'udp';

// The queue producer whose rows are CVE matches over a service's IDENTITY (program + version). Community cannot import
// Enterprise, so the name is declared here and Enterprise's test holds it equal to its `INTELLIGENCE_ENGINE_SOURCE`.
export const CVE_MAPPER_PRODUCER = 'intelligence_engine';
const identified = (program) => typeof program === 'string' && program.trim() !== '' && program.trim().toLowerCase() !== 'unknown';

/**
 * WAS THIS UDP PORT MEASURED IN A RUN, FOR THIS PRODUCER? (1.1.1) — ONE decision, called by the delta and by
 * Enterprise's MTTR, so the two channels cannot disagree. `services` is that run's UDP service records on the host
 * (the loader's `udpServicesOf`), or null when the run recorded no service set.
 *
 * - `closed` on the port → MEASURED: the concluder writes it only from ECONNREFUSED, a real negative ("a CLOSED port
 *   was measured, and closure there stands", as for TCP).
 * - `open` → MEASURED for an analysis agent: it reads the fields the probe filled, so it looked and found nothing.
 * - `open` for the CVE MAPPER → MEASURED only when the service was IDENTIFIED (a program that is not `Unknown`, and a
 *   version). The mapper returns nothing and records nothing for an unidentified service (intelligence_engine's
 *   program guard), so an `open` port whose program is `Unknown` would otherwise "resolve" every CVE row on it —
 *   twenty dnsmasq rows on the router corpus — through this exemption's own front door (the audit seat's condition).
 * - anything else (`no response`, `unknown`, the port absent from the set, no set at all) → NOT measured.
 *
 * @returns {{measured: true, basis: string} | {measured: false, kind: 'no-oracle'|'not-answered'|'unidentified', why: string}}
 */
export function udpPortMeasurement(port, producer, services, runName = 'the other run') {
  if (!Array.isArray(services)) {
    return { measured: false, kind: 'no-oracle', why: `${runName} recorded no service set, so nothing says whether a UDP service answered there` };
  }
  const here = services.filter((s) => Number(s?.port) === Number(port));
  const closed = here.find((s) => s?.status === 'closed');
  if (closed) return { measured: true, basis: `${port}/udp closed in ${runName} (${closed.service ?? closed.protocol} closed)` };
  const open = here.filter((s) => s?.status === 'open');
  if (open.length === 0) {
    return { measured: false, kind: 'not-answered', why: here.length
      ? `in ${runName} no UDP service answered on that port (${here.map((s) => `${s.service ?? s.protocol} ${s.status ?? 'no status'}`).join(', ')})`
      : `${runName}'s service set holds no UDP service on that port` };
  }
  if (producer === CVE_MAPPER_PRODUCER) {
    // ⚠️ A VERSION, NOT A PLACEHOLDER: the producers write an absent version as the literal `Unknown`, and the mapper
    // queries a CPE with it, matches nothing and records nothing — so `Unknown` is as absent as null here.
    const id = open.find((s) => identified(s.program) && identified(s.version));
    if (!id) {
      const s = open[0];
      return { measured: false, kind: 'unidentified', why: `in ${runName} the UDP service answered but was not identified (program `
        + `${identified(s.program) ? s.program : (s.program ?? 'absent')}, version ${identified(s.version) ? s.version : (s.version ?? 'absent')}), so the CVE mapper could not have matched it` };
    }
    return { measured: true, basis: `${port}/udp answered in ${runName} (${id.service ?? id.protocol} open · ${id.program} ${id.version})` };
  }
  const s = open[0];
  const who = identified(s.program) ? ` · ${s.program}${s.version ? ` ${s.version}` : ''}` : '';
  return { measured: true, basis: `${port}/udp answered in ${runName} (${s.service ?? s.protocol} open${who})` };
}
// ⚠️ A CVE ROW THAT VANISHED WHILE THE SAME PROGRAM AND VERSION STILL ANSWER WAS NOT FIXED (1.2.0 build 2 — the audit
// seat's ruling on the build-1 smoke). The CVE mapper attributes a CVE on (program, version) alone, so a row present in
// one run only while the IDENTIFIED program AND version at that host:port:transport are the same in both runs cannot
// be a remediation: the vulnerability DATA moved — NVD's answer, the age of a cached answer, an offline store. MEASURED:
// five dnsmasq 2.78 CVEs NVD stopped matching (all "Awaiting Analysis", no configurations) read RESOLVED across the
// published 1.1.0 run and 1.2.0 build 1, with `dns · dnsmasq · 2.78 · open` on 53/udp in both. APPEND-ONLY.
export const VULNERABILITY_DATA_CHANGED_REASON = 'vulnerability-data-changed';

const transportOf = (label) => (typeof label === 'string' ? TRANSPORT_OF_LABEL[label.toLowerCase()] ?? null : null);
/** An identity the CVE mapper could have matched on: a program AND a version, neither absent nor the `Unknown` placeholder. */
export function identityOf(program, version) {
  return identified(program) && identified(version) ? { program: String(program).trim(), version: String(version).trim() } : null;
}
/**
 * THE SERVICE IDENTITY AT host:port:transport IN ONE RUN — the ONE decision both the delta and Enterprise's MTTR call.
 * `services` is that run's service set, every transport (the loader's `servicesOf`); the row's `protocol` is an
 * application LABEL, mapped to its transport by `TRANSPORT_OF_LABEL` on both sides. Only an OPEN, IDENTIFIED service
 * counts; two different identities on one port and transport are AMBIGUOUS and return null, so the rule stays silent
 * rather than choose one. Null also when no set was recorded — no oracle, never "nothing answered".
 */
export function serviceIdentityAt(services, port, protocol) {
  const t = transportOf(protocol);
  if (!Array.isArray(services) || !(Number(port) > 0) || (t !== 'tcp' && t !== 'udp')) return null;
  const ids = new Map();
  for (const s of services) {
    if (Number(s?.port) !== Number(port) || transportOf(s?.protocol) !== t || s?.status !== 'open') continue;
    const id = identityOf(s.program, s.version);
    if (id) ids.set(`${id.program.toLowerCase()}|${id.version}`, { ...id, port: Number(port), transport: t });
  }
  return ids.size === 1 ? [...ids.values()][0] : null;
}
/** The same identified program AND version — both present. Program is compared case-insensitively, version exactly. */
export const sameServiceIdentity = (a, b) => a != null && b != null
  && a.program.toLowerCase() === b.program.toLowerCase() && a.version === b.version;
// A message with every ABSOLUTE local path reduced to what a reader needs (1.2.1, B6-4a): its tail after the LAST
// `node_modules` (the package-relative module, e.g. `@nsasoft/nsauditor-ai-ee/utils/x.mjs`), else its basename. A load
// error names absolute paths, and a client artifact must never carry the operator's directory layout — the rule
// `vulnerabilityDataSource` below states for its own detail. POSIX and Windows paths and a `file://` URL; a path in
// quotes may hold spaces, and so may an unquoted one that ends in a module file (Node's "imported from <path>"). A path
// whose closing quote was cut off is still reduced: an opening quote is a lead for the unquoted rules too.
const QUOTED_PATH = /(['"`])((?:file:\/\/)?(?:\/|[A-Za-z]:\\)[^'"`\n]*)\1/g;
const UNQUOTED_MODULE_PATH = /(^|[\s(='"`])((?:file:\/\/)?(?:\/|[A-Za-z]:\\)[^'"\n]*?\.(?:mjs|cjs|js|json|node)(?::\d+)*)(?=$|[\s'"),;])/g;
const UNQUOTED_PATH = /(^|[\s(='"`])((?:file:\/\/)?(?:\/|[A-Za-z]:\\)[^\s'"()]+)/g;
function shortPath(p) {
  const s = p.replace(/^file:\/\//, '');
  const i = Math.max(s.lastIndexOf('node_modules/'), s.lastIndexOf('node_modules\\'));
  return i >= 0 ? s.slice(i + 'node_modules/'.length) : (s.split(/[\\/]/).filter(Boolean).pop() ?? '');
}
export function withoutLocalPaths(text) {
  return String(text)
    .replace(QUOTED_PATH, (_, q, p) => `${q}${shortPath(p)}${q}`)
    .replace(UNQUOTED_MODULE_PATH, (_, lead, p) => `${lead}${shortPath(p)}`)
    .replace(UNQUOTED_PATH, (_, lead, p) => `${lead}${shortPath(p)}`);
}
/**
 * WHERE A RUN'S VULNERABILITY DATA CAME FROM, in words, from its run record's `nvdCache` — never a local path, which
 * would carry the operator's directory layout into a client artifact. `state` is the offline store's (`absent` means
 * none was imported, so the NVD API answered, through the response cache when it held the entry).
 */
export function vulnerabilityDataSource(nvdCache) {
  if (!nvdCache || typeof nvdCache !== 'object') return 'not recorded';
  if (['fresh', 'stale', 'undated'].includes(nvdCache.state)) return `an offline NVD store (${nvdCache.state})`;
  const rc = nvdCache.responseCache;
  const day = (t) => (typeof t === 'string' ? t.slice(0, 10) : null);
  if (rc?.present === true && day(rc.oldestAt)) {
    const a = day(rc.oldestAt); const b = day(rc.newestAt) ?? a;
    return `NVD answers cached up to ${rc.ttlDays} days, fetched ${a === b ? a : `${a} to ${b}`}`;
  }
  return 'the NVD API, asked live';
}
// The gap class Enterprise's service-set input gap stamps (`evidence.raw.gapClass`). Spelled ONCE, here, on
// the reading side: Enterprise imports it, so the producer and this reader cannot drift to two spellings.
export const INPUT_GAP_CLASS = 'input_gap';

// ⚠️ RUNS ARE NAMED ABSOLUTELY IN EVERY DETAIL (1.1.1 — the audit seat's T1-c fold 1). The executive page prefixes a
// not-comparable row with its direction in absolute terms ("absent from this run" / "appeared in this run", this run =
// the CURRENT run), and the details used to name runs RELATIVE to the side holding the row ("in the other run") — which
// for a row that DISAPPEARED is also the current run, so the assembled line placed a current-run failure in the
// baseline. The call site knows the frame and passes it; `udpPortMeasurement` keeps "the other run" only as its DEFAULT,
// because Enterprise's MTTR rewords that phrase for its own frame.
export const RUN_NAMES = Object.freeze({ current: 'this run', baseline: 'the baseline run' });
const FRAME_DISAPPEARED = Object.freeze({ mine: RUN_NAMES.baseline, theirs: RUN_NAMES.current });
const FRAME_APPEARED = Object.freeze({ mine: RUN_NAMES.current, theirs: RUN_NAMES.baseline });

export const NOT_COMPARABLE_REASONS = Object.freeze([
  'host-not-scanned',              // the other run never wrote this host
  'producer-unknown',              // the finding carries no producer identity to adjudicate
  PLUGIN_NOT_RUN_REASON,           // the producing plugin was not requested in the other run
  'evidence-gap',                  // a producer DECLARED it could not read the surface
  PLUGIN_NOT_MEASURED_REASON,      // the plugin was attempted on the host and errored / timed out / was skipped
  'framework-enumeration-changed', // the control left or joined the enumeration between the runs
  IDENTITY_BASIS_CHANGED_REASON,   // the producer changed WHAT IT NAMES between the two releases
  SCOPE_NOT_SCANNED_REASON,        // the finding's coverage unit was outside the OTHER run's recorded scope
  PROBE_NOT_MEASURED_REASON,       // a probe ran on the finding's port, open per the port scanner, and did not complete there
  PORT_NOT_MEASURED_REASON,        // the finding's port was open in its run and neither open nor closed in the other (filtered / unprobed)
  VULNERABILITY_DATA_CHANGED_REASON, // a CVE row in one run only, the same program AND version identified on its port in both
]);

/**
 * WHEN EACH PRODUCER LAST CHANGED WHAT IT NAMES AS A FINDING'S OBJECT.
 *
 * A finding's identity is keyed partly on `resource`. Canonicalisation (`finding_identity.mjs`)
 * makes an old decorated value and a new clean one compute the SAME key, so a producer that
 * always named its object compares across an upgrade unchanged. It cannot do that for a producer
 * that GAINED an identity: a finding keyed on `'-'` in the baseline and on `sg-0def2…` in the
 * current run is one exposure wearing two keys, and a naive delta reports it as one RESOLVED
 * plus one NEW — a fabricated remediation and a fabricated exposure in the same table, on the
 * feature's headline use.
 *
 * The alternative was bumping `RUN_RECORD_SCHEMA`, which refuses EVERY pre-upgrade baseline
 * outright — including for the ~20 producers that did not move. Per-producer declaration pays
 * the cost in DISCLOSURE instead: the affected producer's rows are declared not comparable and
 * every other producer's delta stands.
 *
 * ⚠️ THIS TABLE IS A CLAIM SURFACE IN BOTH DIRECTIONS AND BOTH ARE FATAL. An UNDECLARED mover
 * fabricates churn — the defect this exists to prevent. A DECLARED producer that did NOT move
 * throws away a real comparison, silently, for ever. It is held in equality with what the
 * artifacts actually show by `tests/identity_basis_instrument.test.mjs`, which derives the mover
 * set by running THIS loader over a pre-change run and a post-change run and comparing the key
 * sets for the same objects. **Derive it; never hand-edit it to match a prediction.**
 *
 * The nine members are E1's own movers: 1150 / 1170 / 1190 claimed a REGION as their object and
 * now name the real one; 1020 / 1024 / 1025 / 1030 / 1200 / 1210 named nothing and now name an
 * object or their scope. `null → a value` moves a key exactly as `region → object id` does.
 */
/**
 * THE NON-NUMERIC PRODUCERS A DECLARATION MAY NAME.
 *
 * ⚠️ THE TABLE BELOW WAS KEYED ON PLUGIN IDS AND PINNED `/^\d{3,4}$/`, because every declared
 * producer was a plugin. Enterprise's ANALYSIS AGENTS are producers too — a finding out of the
 * finding QUEUE carries `evidence.source` as its identity, never an id — and one of them changes
 * what it names at EE 1.1.0. So the vocabulary has to widen, and widening it to "any string" is
 * not an option: a typo would declare a producer that does not exist, `identityBasisChanged` would
 * find nothing on lookup, and the REAL producer would stay undeclared and fabricate churn. That is
 * the defect the table exists to prevent, arriving through the table's own key.
 *
 * ⚠️ IT IS DECLARED HERE AND DERIVED THERE. Community cannot see Enterprise's agent registry, and
 * Enterprise cannot edit this file — so a hand list in either repo is a copy that rots when the
 * other side moves. `tests/agent_producer_vocabulary.test.mjs` in EE holds this set in TWO-WAY
 * equality with the set derived from EE's own registry and its mapper's exported source constant:
 * a member here that EE does not emit fails, and a source EE emits that is missing here fails too.
 * A subset check in either direction would be a superset guard, structurally unable to catch the
 * other side's omission.
 */
export const AGENT_PRODUCER_KEYS = Object.freeze([
  'auth_agent', 'crypto_agent', 'config_agent', 'service_agent', 'exposure_agent',
  'intelligence_engine',
]);

export const IDENTITY_BASIS_CHANGED_AT = Object.freeze({
  1020: '1.1.0', 1024: '1.1.0', 1025: '1.1.0', 1030: '1.1.0',
  // ⚠️ 1040 JOINS AT THE STAMP, LIKE 1120 BELOW. Every CloudTrail-auditor row carried NO region at all
  // (20 of 20 on build 4's pack), so `scopeNotScanned` read each as account-wide; EE build 5 stamps
  // the region of the object a row is about (a trail's home region, a trail bucket's own location,
  // config.region for the alarm and Config checks). That puts `region` into `keyOf` and CHANGES WHAT
  // THOSE FINDINGS ARE, so the straddle is declared exactly as 1120's was.
  1040: '1.1.0',
  // ⚠️ 1110 IS A THIRD KIND: A TEXT CORRECTION, NOT A RENAMED OBJECT OR A NEW REGION. Its HIGH row
  // (kms:Decrypt on Resource:*) told the reader the KMS key-policy and grant layers had been
  // cross-referenced under a HIGH→INFO downgrade contract — and from EE 1.1.0 build 5 that downgrade
  // runs on no shipped path, because a one-region read cannot establish that no key trusts a
  // principal (CFN-3). The corrected sentence changes the row's content digest, which is part of
  // `keyOf`, so every such HIGH straddling the upgrade would read as one finding resolved and a new
  // one appearing. Declared for the same reason as the rest: what identifies the finding changed.
  1110: '1.1.0',
  // ⚠️ 1120 JOINS AT THE STAMP, NOT AT THE RENAME. Its replication and lifecycle rows recorded
  // their region as `details.sourceBucketRegion` and carried NO top-level `region`, so in this
  // engine's frame they were non-regional: `scopeNotScanned` skipped them and narrowing a later
  // scan away from the source region read them as REMEDIATED. Stamping the field the loader
  // actually reads puts `region` into `keyOf`, which CHANGES WHAT THOSE FINDINGS ARE — 36 of its
  // 297 archived rows gain one — so the straddle must be declared like any other basis change.
  // 1200 and 1210 take the same stamp and are already declared above; only 1120 was new.
  1120: '1.1.0',
  1150: '1.1.0', 1170: '1.1.0', 1190: '1.1.0', 1200: '1.1.0', 1210: '1.1.0',
  // ⚠️ 1023 JOINS AT BUILD 12, BATCHED WITH THE SIX ABOVE SO CUSTOMERS TAKE ONE 1023 STRADDLE, NEVER TWO. Two of the
  // four rows the build-11 delta called RESOLVED were 1023's and no port rule could reach them: "FTP port open —
  // verify no anonymous or default credentials" is emitted BECAUSE 21 is open yet carried no port, and the exposure
  // row carried its COUNT in the title, so 16 → 15 open ports read as a fix plus a new finding. Build 12 attaches the
  // gating port to every row emitted because one port is open (21 · 22 · 23 · 3389 · 5900) and gives the exposure
  // rows one count-free title with the count in details. Both put new values into `keyOf` — `port`, `title` — which
  // CHANGES WHAT THOSE FINDINGS ARE, so the straddle is declared like 1040's region stamp.
  1023: '1.1.0',
  // ⚠️ AN ANALYSIS AGENT, NOT A PLUGIN, AND THE FIRST NON-NUMERIC KEY THIS TABLE HAS HELD. A
  // finding from Enterprise's finding QUEUE emits no resource, no region, no identity qualifier
  // and no content digest, so `keyOf` reduces to `host · producer · port · TITLE` — the title IS
  // what this producer names. EE 1.1.0 moved the coverage-gap title off `${program} ${version}`,
  // a discovery fingerprint that changes when the scan does (measured: one service came back
  // `DNS-SD/mDNS` in one run and `Unknown` in the next, same port, same host), and onto
  // `${protocol}/${service}`. Same definition as the nine above, read off the field that carries
  // the answer in this container.
  //
  // The key is bounded by `AGENT_PRODUCER_KEYS` and held in two-way equality with what Enterprise
  // actually emits, because a key outside the vocabulary can never match a finding — and a
  // declaration that matches nothing is SILENT while the real producer stays undeclared.
  intelligence_engine: '1.1.0',
});

// ⚠️ NO SECOND COMPARATOR. This file already has `cmpVersion` (below, used by the
// finding-count-semantics boundary) and my first draft shipped a duplicate beside it — two
// version comparators in one module is exactly how two call sites come to disagree about what
// "earlier" means. `String(null)` parses to 0 there, so a null baseline version sorts BEFORE any
// release, which is the behaviour this declaration needs: a run record with no `eeVersion`
// predates every declared change.

/**
 * Did this producer's identity basis change BETWEEN the two runs?
 * True only when the baseline predates the declared change and the current run is at or after
 * it — never merely because the versions differ, which would declare on every upgrade for ever.
 */
export function identityBasisChanged(plugin, baselineEeVersion, currentEeVersion) {
  const at = IDENTITY_BASIS_CHANGED_AT[plugin];
  if (!at) return false;
  return cmpVersion(baselineEeVersion, at) < 0 && cmpVersion(currentEeVersion, at) >= 0;
}

// ⚠️ THERE IS NO DISPLAY-LABEL MAP HERE, AND THE REASON IS A MEASUREMENT.
//
// `plugin-identity-basis-changed` was named when every declared producer WAS a plugin. EE 1.1.0
// declares an analysis AGENT, and both render seams build their cell as `${f.reason}: ${f.detail}`
// — so the row read "plugin-identity-basis-changed: producer intelligence_engine changed what it
// names ...", detail repaired and CODE still asserting "plugin" about an agent.
//
// The first repair added a render-time LABEL map and kept the code, justified by: "the vocabulary
// is append-only under SCAN_DELTA_SCHEMA; renaming changes what a consumer's stored verdicts
// MEAN." That premise is CHECKABLE and was not checked. Measured against the published artifact
// rather than against git — git answers about the repo, not about what a consumer holds —
// `npm pack nsauditor-ai@0.2.54` does not contain THIS FILE at all, and the string appears
// nowhere in those bytes (positive control: `utils/report_inputs.mjs` present, 47 files in
// `utils/`). The engine is unpublished: zero stored verdicts carry the code, and no guard in
// either repo ever stated the append-only rule.
//
// The map was also actively worse than the rename. It was a SECOND COPY of the outcome's spelling,
// free to drift from the code it stood in for; and it moved ONE of two human surfaces, so the
// terminal said `plugin-identity-basis-changed` while the client HTML said `identity basis
// changed` — one outcome under two names, which makes a support call unanswerable. The code is
// renamed instead: one spelling, true of a plugin and of an agent alike, on every surface that
// interpolates it — including any seam added later, which a per-seam label can never cover.

// Whole-comparison refusals: cases where NO per-finding verdict is trustworthy, so none is offered.
export const REFUSAL_REASONS = Object.freeze([
  'ee-presence-differs',
  'tier-differs',
  'finding-count-semantics-boundary',
  'run-record-schema-differs',
  'baseline-chain-broken',
  'baseline-integrity-unmeasurable',
]);

// ⚠️ SEPARATE, AND DELIBERATELY SO. `tests/scan_delta.test.mjs` holds `REFUSAL_REASONS` in EXACT
// equality with the `refuse('…')` calls in THIS file — a guard that catches both a new code that
// forgets the constant and a code deleted from the constant while still produced. A view-level
// refusal put into that array breaks the equality, and the only way to keep one array would be to
// relax it to a SUBSET check: a superset guard, which this repo's own notes call structurally
// incapable of catching an omission. So the vocabulary is still one thing to a reader
// (`DECLARED_OUTCOMES` unions them) and two things to the two derivations that can each stay
// EXACT. Raised by `scan_delta_view.mjs`, never by `buildScanDelta`: the baseline record exists
// but this build cannot read it — a schema it does not understand, or a corrupt file.
export const VIEW_REFUSAL_REASONS = Object.freeze([
  'baseline-unloadable',
]);

// ⚠️ THE BOUNDARY CONTRACT. Three fields were dropped at ONE seam before this existed —
// `resource` (a new exposure masked), `plugin` (every comparison fell to plugin-not-run) and
// `control` (a finding whose control left the enumeration read as RESOLVED). Each was invisible
// to this module's own tests because each fixture was built by hand with the field present: a fix
// verified only against fixtures the author constructs is verified against the author's idea of
// the input. `tests/delta_boundary_contract.test.mjs` asserts CONSUMED ⊆ EMITTED ∪ DECLARED_ABSENT
// against the REAL loader, so the fourth instance fails by name instead of shipping.
export const CONSUMED_FINDING_FIELDS = ['host', 'plugin', 'pluginName', 'producerKind', 'evidenceGap', 'gapClass', 'deferredScope',
  'contentDigest', 'identityQualifier', 'resource', 'region', 'port', 'protocol', 'title', 'severity', 'control'];

// Fields this module WRITES onto its output records; they are never read from a loaded finding,
// so they must not be demanded of the loader. Declared so the derivation can subtract them.
export const OUTPUT_ONLY_FINDING_FIELDS = ['reason', 'detail', 'direction', 'from', 'to', 'basisNote'];

// A consumed field the loader legitimately cannot produce. NOT a bare allowlist: each entry names
// the limit that DISCLOSES its absence, and the guard verifies that limit is actually emitted —
// a carve-out whose premise nobody checks is how an absence becomes a silent pass.
// ⚠️ EVERY DECLARATION NAMES THE PATH IT EXCUSES. A finding reaches the delta through one of two
// containers — a plugin ENVELOPE (`shapeFinding`) or the finding QUEUE (`shapeQueueEntry`) — and
// they have different vocabularies. An unqualified declaration excuses a field on BOTH, so the
// day either container stopped emitting it the carve-out would already be there to cover it.
export const DECLARED_ABSENT_FINDING_FIELDS = {
  control: {
    paths: ['plugin', 'queue'],
    reason: 'Community ships no compliance data (data/compliance is empty) and report_inputs.mjs '
      + 'emits no control id, so a CE run record cannot carry one. Compliance routing is EE\'s.',
    disclosedBy: 'FRAMEWORK_MOVEMENT_NOT_EVALUATED',
  },
  // ── QUEUE-PATH ABSENCES ───────────────────────────────────────────────────────────────────
  // Found because the guard above had never been asked about this path: its fixture built a
  // plugin envelope, so CONSUMED ⊆ EMITTED was checked against one container and believed of two.
  contentDigest: {
    paths: ['queue'],
    reason: 'The digest exists because PLUGIN titles are SYNTHESISED from `issues` and CUT at 160 '
      + 'characters — three CRITICAL ingress rules on one security group once synthesised to the '
      + 'same 158-character string and held one identity. A queue title is AUTHORED by its '
      + 'producer and never truncated, so the collision the digest was built for cannot arise on '
      + 'this path. A digest here would have to hash the DESCRIPTION, which carries the same '
      + 'volatile program name that EE 1.1.0 is moving OUT of identity — the volatility would '
      + 'return through the digest. A collision that does occur anyway is named, per identity, at '
      + 'runtime by IDENTITY_COLLAPSE.',
    disclosedBy: 'AGENT_SCOPE_FROM_TIER',
  },
  identityQualifier: {
    paths: ['queue'],
    reason: 'A producer-emitted rule discriminator (`details.groupId` / protocol / port range). '
      + 'Analysis agents emit no rule ids and carry no `details` object at all, so there is '
      + 'nothing to qualify with. The key falls back rather than requiring it.',
    disclosedBy: 'AGENT_SCOPE_FROM_TIER',
  },
  resource: {
    paths: ['queue'],
    reason: 'A cloud noun — the object a cloud producer names. A queue finding is scoped to a '
      + 'HOST and a PORT, which the path does emit; inventing a resource for it would put a '
      + 'fabricated object identity into the delta key.',
    disclosedBy: 'AGENT_SCOPE_FROM_TIER',
  },
  region: {
    paths: ['queue'],
    reason: 'A cloud coverage unit. Queue findings come from network analysis agents, which have '
      + 'no region; `scopeNotScanned` is silent for a finding with no unit, which is the correct '
      + 'reading — a narrowed region says nothing about a port on a network host.',
    disclosedBy: 'AGENT_SCOPE_FROM_TIER',
  },
};


// ⚠️ DERIVED FROM THE FROZEN CONTRACT, NOT INVENTED HERE. `docs/contract-v1.md` §5.3: the
// `findingCount` key KEPT ITS NAME AND CHANGED ITS VALUE in the first release after EE 0.46.0 —
// every archived pack before that release printed the ISSUE count under it. A delta spanning that
// boundary would report a mass remediation that never happened, so it is REFUSED, not annotated.
export const FINDING_COUNT_BOUNDARY_EE = '0.46.0';

// The honest label, and it rides in the OUTPUT rather than only in the docs: a hash chain on the
// same disk as the records it covers is defeated by anyone who can recompute the successors.
export const CHAIN_ASSURANCE_LABEL =
  'Baseline integrity is tamper-EVIDENT against accidental corruption, partial restore and ' +
  'unsophisticated edits. It is NOT tamper-proof against an attacker with host-level access, ' +
  'and it is not non-repudiation: the chain carries no signature and names no author.';

// EXPORTED so a consumer that asks "was this written before release X?" asks it with THIS
// comparator — Enterprise's MTTR loader gates its region-identity warning on it (item 26). The "no
// second comparator" rule above holds across the two packages, not only within this file.
export const cmpVersion = (a, b) => {
  const pa = String(a).split('.').map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i += 1) if ((pa[i] ?? 0) !== (pb[i] ?? 0)) return (pa[i] ?? 0) < (pb[i] ?? 0) ? -1 : 1;
  return 0;
};

// ⚠️ IDENTITY MUST CARRY THE RESOURCE, and the first draft of this did not — a HIGH defect an
// independent seat found by reading the FIXTURES rather than the code. Cloud issue strings carry
// the DEFECT, not the resource ("No public access block configured…"), so twelve buckets with one
// misconfiguration share a title; resource identity lives in `finding.resource` (contract-v1 §1.1).
// Under a host+plugin+title key those twelve collapse to ONE, and the failure is in the dangerous
// direction: fix bucket-c, acquire bucket-d with the same defect, and the delta reported
// "unchanged" — A NEW EXPOSURE ABSENT FROM `newFindings` ENTIRELY, measured, not theorised.
//
// ⚠️ `severity` IS DELIBERATELY NOT IN THE KEY. Adding it would render one escalation as a
// resolved finding PLUS a new one — two false verdicts from one true change. Identity first, then
// severity compared between MATCHED findings into `changed`.
//
// ⚠️ `originalIndex` IS NOT A CANDIDATE, though contract-v1 §1.2 freezes it on every record: it is
// the index in the INPUT array and all fan-out records of one cloud finding SHARE it (§1.2:53).
// Positional and non-unique — adopting it as an id would be worse than this composed key.
// ⚠️ NO `?? f.target` FALLBACK, and its removal is the F5 lesson applied to a benign case. The
// boundary guard flagged `target` as consumed-but-never-emitted on its FIRST run: report_inputs
// already folds target INTO resource (`resource: f?.resource ?? f?.target ?? …`), so a finding can
// never reach here carrying a bare target. A fallback that cannot fire through the shipped path is
// not defensive depth — it is dead code that reads as coverage, which is exactly what made the
// framework-enumeration leg look complete while being inert.
// ⚠️ NEVER OVER A TRUNCATED STRING. The title is SYNTHESISED and CUT AT 160 CHARS for producers
// that emit none, and on a live estate three world-open ingress rules on one security group
// differed only past the cut — one identity for three CRITICAL exposures, so a NEW world-open
// database port would have read as UNCHANGED. `contentDigest` covers the untrucated content and
// `identityQualifier` carries the producer's OWN rule discriminators; the title remains the
// fallback for anything emitting neither.
// ⚠️ BOTH `title` AND `contentDigest`, NEVER ONE INSTEAD OF THE OTHER — measured, and the first
// draft got it wrong in the dangerous direction. `contentDigest ?? title` looked equivalent-or-
// better and was STRICTLY COARSER for producers that emit no raw title: 1020 names the bucket only
// in the SYNTHESISED title, while the digest covers `[rawTitle, issues]` where rawTitle is null and
// the issue text carries no bucket. Two different S3 buckets — `aws-config-logs-…` and
// `cloudtrail-violator-logs-…` — hashed identically and collapsed. The fix for one producer's
// masking re-created it at another, which is why this was caught on the REAL record and not by the
// fixtures written from 1170.
//
// Taking both is strictly finer than either: the digest separates content that TRUNCATION hid, the
// title separates naming the digest never saw, and the qualifier separates rules that share both.
//
// ⚠️ `region` IS A COMPONENT SINCE E1, AND REMOVING THE SUFFIX WITHOUT ADDING IT WOULD COLLAPSE
// A POPULATION. Before E1 the region entered this key only as decoration inside `resource`
// (` [us-east-1]`, appended downstream by EE's `_stampRegion`), so a per-region finding that
// names no object — a scope literal like `backup:account`, emitted once per region — was
// separated ONLY by that suffix. De-suffixing alone would have mapped every region's copy onto
// one key and reported N-1 of them as removed. It is taken from the finding's own FIELD, which
// both sides of any comparison recompute identically, so unlike a suffix it fabricates nothing
// across an upgrade.
// The host is compared by `hostKey` (census G6): one host is one host whatever case it was typed in.
const keyOf = (f) => [hostKey(f.host), f.plugin, f.resource ?? '-', f.port ?? '-',
  f.region ?? '-', f.identityQualifier ?? '-', f.title, f.contentDigest ?? '-'].join('|');

// A plugin status that means THE SURFACE WAS NOT READ. `ran` is the only status that licenses a
// comparison; the rest are the machine saying so itself.
// ⚠️ EXPORTED AS A FROZEN LIST, NOT AS THE SET. Enterprise's MTTR engine reads the same vocabulary
// (a prior row whose plugin was not measured now is not closed), and a shared Set is one any
// importer could `add` to. The vocabulary is CLOSED: `tests/scan_delta.test.mjs` holds every
// status literal the plugin manager assigns inside MEASURED_STATUS ∪ NOT_MEASURED_STATUSES.
export const MEASURED_STATUS = 'ran';
export const NOT_MEASURED_STATUSES = Object.freeze(['error', 'timeout', 'skipped']);
const NOT_MEASURED_STATUS = new Set(NOT_MEASURED_STATUSES);

// ⚠️ SCOPE IS WHAT A RUN MEASURED, WHICH IS NARROWER THAN WHAT IT REQUESTED IN THREE WAYS, and
// every one of them was fail-open here until 2026-09-20 — each produced a `resolved` row in a
// CLIENT artifact when driven through `report --since`:
//   HOSTS were `hostsRequested ∪ hostsWritten`, so a host that was asked for and never produced
//     output counted as scanned and its baseline findings read as remediation.
//   PLUGIN STATUS was not consulted at all, though the loader has always carried it, so a plugin
//     that ERRORED or TIMED OUT on a host counted as having measured it.
//   EVIDENCE GAPS were read from `side.evidenceGaps`, which NO shipped caller ever populated —
//     dead since the day it was written, and the fall-through from a dead leg is `resolved`.
// ⚠️ THE `side.evidenceGaps` READ IS DELETED RATHER THAN REPAIRED. It was unreachable AND
// shape-wrong: the only producer of that record shape (`cloud_finding_summary.mjs`) builds
// `plugin: String(r?.id ?? '')` with NO `host` key at all, so even a caller that filled it would
// key `undefined|1170` against a lookup keyed `<host>|<id>`. Leaving a second unreachable path
// beside the repaired one is the F5 mistake this module already records at the framework leg —
// dead code that reads as coverage.
/**
 * The COVERAGE UNIT a finding sits in, per provider, and whether the OTHER run recorded covering
 * it. Returns a detail string when the finding is outside that run's recorded scope, else null.
 *
 * Each provider resolves a different unit, so the unit is read per provider rather than assumed:
 *   aws    → REGION,       carried per finding as `f.region`
 *   azure  → SUBSCRIPTION, carried by the HOST (every finding of that host shares it)
 *   gcp    → PROJECT,      likewise
 *
 * ⚠️ THREE SILENCES, EACH DELIBERATE. (1) BOTH sides unknown → silent: every record written
 * before this field existed lacks it, and firing there would turn every historical comparison
 * into a wall of rows. (2) A finding with NO unit (`iam:account`, no region) is not scoped by
 * that unit and is untouched — otherwise a narrowed region makes the whole account
 * not-comparable. (3) A side that DISAGREED with itself about its coverage is UNKNOWN, not
 * covered: the resolver memo is keyed on the credential fingerprint, so two keys resolving
 * different sets inside one host's scan means the run has no single coverage to difference.
 */
// ⚠️ IMPORTED, NOT DECLARED HERE — this module's ONLY import, and it buys the removal of a
// second copy. Enterprise's CPE mapper needs the same provider list to know that a cloud host
// has no service-feeding upstreams; `utils/cloud_providers.mjs` is the single home and derives
// its host set from THIS map's keys, so adding a provider is one edit in one file.
import { PROVIDER_SCOPE_UNIT, canonicalHost, hostKey } from './cloud_providers.mjs';

// ── A PORT THE RUN COULD NOT MEASURE (EE 1.1.0 build 9, F6) — one decision, shared with Enterprise's MTTR ──
/** A port-scoped input gap: Enterprise's record that a probe could not complete on this port. */
// Written as plain `f.` reads so the boundary contract's derivation SEES them (it reads `f.<field>`; an
// optional chain is invisible to it, and `gapClass` would read as consumed-but-undeclared).
export const isPortInputGap = (f) => f != null && f.evidenceGap === true && f.gapClass === INPUT_GAP_CLASS && Number(f.port) > 0;
/** The key a port gap is looked up by — `hostKey`, so a host typed in two cases is one host. */
export const portGapKey = (host, port) => `${hostKey(host)}|${Number(port)}`;
/** Every port a run could not measure: `portGapKey` → the gap's title (what the reader is told). */
export function portsNotMeasured(findings) {
  const out = new Map();
  for (const f of Array.isArray(findings) ? findings : []) {
    if (!isPortInputGap(f)) continue;
    const k = portGapKey(f.host, f.port);
    if (!out.has(k)) out.set(k, f.title ?? 'an input gap was recorded on this port');
  }
  return out;
}

/**
 * Per host, what the port scanner recorded: `hostKey` → { open: Set, closed: Set }. Read from the loader's
 * `portScan`, which it sets only where 003 RAN and carried both lists. Two directories naming one host whose scans
 * DISAGREE about a port are resolved conservatively: a port counts as open if either saw it open and as closed only
 * if some scan closed it — the verdict below needs "open on one side" AND "in neither list on the other".
 */
function portStateOf(byHost) {
  const out = new Map();
  for (const h of Array.isArray(byHost) ? byHost : []) {
    const k = hostKey(h?.host);
    const ps = h?.portScan;
    if (ps && Array.isArray(ps.tcpOpen) && Array.isArray(ps.tcpClosed)) {
      const e = out.get(k) ?? {};
      e.open ??= new Set(); e.closed ??= new Set();
      for (const p of ps.tcpOpen) if (Number(p) > 0) e.open.add(Number(p));
      for (const p of ps.tcpClosed) if (Number(p) > 0) e.closed.add(Number(p));
      out.set(k, e);
    }
    // The UDP oracle (1.1.1): the loader's `udpServices` — present only where the run recorded a service set. Two
    // directories of one host pool their records, as their TCP lists do above.
    if (Array.isArray(h?.udpServices)) {
      const e = out.get(k) ?? {};
      e.udpServices = [...(e.udpServices ?? []), ...h.udpServices];
      out.set(k, e);
    }
    // Every transport's service identities (1.2.0 build 2) — the loader's `servicesOf`, for `serviceIdentityAt`.
    if (Array.isArray(h?.services)) {
      const e = out.get(k) ?? {};
      e.services = [...(e.services ?? []), ...h.services];
      out.set(k, e);
    }
  }
  return out;
}

function scopeNotScanned(f, mine, theirs, names) {
  const provider = hostKey(f?.host);
  const mineEntry = mine?.scopeScanned?.[provider] ?? null;
  const theirEntry = theirs?.scopeScanned?.[provider] ?? null;
  if (!mineEntry && !theirEntry) return null;                 // (1) neither side knows

  // ⚠️ THE UNIT IS A PROPERTY OF THE PROVIDER, NEVER OF THE RECORD ENTRY — and the first draft
  // had it the other way round, which made the both-sides-unknown guard DEAD CODE: with no entry
  // on either side the unit fell back to a literal that is not 'region', so the value lookup
  // returned null and the guard below caught every case first. A mutant deleting guard (1)
  // survived the whole fixture set, which is how it was found. Reading the unit from the provider
  // makes the guard load-bearing: a pre-fix pair with a regional finding now reaches it.
  const unitName = PROVIDER_SCOPE_UNIT[provider] ?? null;
  if (unitName === null) return null;              // a provider with no coverage unit of its own
  // ⚠️ THE UNIT COMES FROM THE FINDING'S OWN SIDE, NEVER BORROWED FROM THE OTHER — and borrowing
  // was a live defect. A region RIDES ON the finding, so a finding's existence proves its own run
  // covered that region and the only unknown is ever the OTHER side's coverage; that asymmetry is
  // deliberate. A subscription or project rides on the HOST, so when the finding's own record
  // carries no scope there is nothing to say WHICH subscription it belonged to. Reading
  // `mineEntry ?? theirEntry` made `covered.has(value)` true by construction: measured, a baseline
  // azure finding whose record lacked the field read RESOLVED against a current scoped to a
  // DIFFERENT subscription — the first delta after upgrading, on a possibly different estate.
  let value;
  if (unitName === 'region') {
    value = typeof f?.region === 'string' && f.region ? f.region : null;
    if (value === null) return null;                          // (2) not a regional finding
  } else if (!mineEntry) {
    // Guard (1) already returned when NEITHER side knows, so the other side does know — and this
    // finding's own run does not. Which unit it belongs to is unknowable, so it fails closed.
    return `${names.mine}'s record carries no ${unitName} scope, so which ${unitName} this finding `
      + `belongs to is not known — it cannot be called fixed or new against ${names.theirs}`;
  } else {
    value = mineEntry.scanned?.[0] ?? null;
    if (value === null) return null;                          // (2) recorded an empty scope
  }

  if (!theirEntry) {
    return `${names.theirs}'s record carries no ${unitName} scope, so it is not known whether `
      + `${unitName} ${value} was covered there — this finding cannot be called fixed or new `
      + 'against an unknown scope';
  }
  if (theirEntry.disagreed === true || mineEntry?.disagreed === true) {
    return `a run disagreed with itself about which ${unitName}s it covered, so its scope is `   // (3)
      + `unknown; ${unitName} ${value} cannot be differenced against it`;
  }
  const covered = new Set(Array.isArray(theirEntry.scanned) ? theirEntry.scanned : []);
  if (covered.has(value)) {
    // ⚠️ THE RUN-LEVEL SET IS A UNION, AND A UNION IS NOT A STATEMENT ABOUT ONE PRODUCER. It is
    // every region ANY producer resolved in that run, so a record saying `[us-east-1, eu-west-1]`
    // can contain a producer that only ever looked at `us-east-1` — 1200 resolves regions ONLY
    // under an explicit `awsRegionIntent`, and several plugins iterate no regions at all. Without
    // this refinement the check answers "eu-west-1 WAS covered", the finding is differenced, and a
    // surface that producer never examined reads as REMEDIATED: the same defect `scope-not-scanned`
    // exists for, one level of granularity down.
    //
    // ⚠️ A MISSING ENTRY IS NOT A NEGATIVE, and that asymmetry is the rule. `byPlugin` refines
    // only where it SPEAKS: no map at all is every record written before the field shipped, and a
    // map without THIS producer means the run made no statement about it — a producer that earns
    // no entry because it resolves no regions is the BACKSTOP's subject, adjudicated on its own
    // terms. Reading either silence as "covered nothing" would fire on the ABSENCE of information
    // and refuse every archived comparison at once.
    const perProducer = theirEntry.byPlugin?.[String(f?.plugin)];
    if (Array.isArray(perProducer) && !perProducer.includes(value)) {
      return `${unitName} ${value} is inside ${names.theirs}'s overall scope, but producer `
        + `${f.plugin} only covered ${perProducer.join(', ') || 'no ' + unitName + 's'} there — `
        + 'the run-level set is the union across producers, so this surface was not looked at by '
        + 'the producer that would have found it, which is not the same as the finding being fixed';
    }
    return null;                                              // genuinely comparable
  }
  return `${unitName} ${value} was outside ${names.theirs}'s recorded scope `
    + `(${[...covered].join(', ') || 'none recorded'}) — the surface was not looked at there, `
    + 'which is not the same as the finding being fixed';
}

const scopeOf = (side) => {
  const rec = side?.record ?? {};
  // ⚠️ EVERY HOST HERE IS A `hostKey` (census G6). This set and `scopeScanned` below come from the RAW
  // record, not the loader's model, so a record written as `AWS` before the parse-time fold — or a host
  // typed `MyHost.local` in one run and `myhost.local` in the next — must be keyed HERE, or the pair
  // reads host-not-scanned. And the gap and statement maps are keyed the same way: a host set that paired
  // across case while the gap map did not would lose the other run's gap and call its finding RESOLVED.
  // What a reader is SHOWN keeps the recorded spelling (`hostNames`).
  const hostNames = new Map();
  const keyHost = (h) => {
    const k = hostKey(h);
    if (k && !hostNames.has(k)) hostNames.set(k, canonicalHost(h));
    return k;
  };
  const hosts = new Set((rec.hostsWritten ?? []).map((h) => keyHost(h?.host)).filter(Boolean));
  const plugins = new Set(rec.pluginsRequested ?? []);
  const gaps = new Map();
  // Gaps as the PRODUCER records them — on the finding, where they already ride.
  // ⚠️ EXCEPT A PORT-SCOPED INPUT GAP (EE 1.1.0 build 9). Enterprise emits one per analysis agent for each
  // port a probe could not measure, so keyed here by PRODUCER it would set aside that agent's rows on EVERY
  // port of the host, and a genuine fix on a port that WAS measured would stop reading resolved. It is
  // scoped to its port, in `portGaps`, and nowhere else.
  for (const fi of side?.findings ?? []) {
    if (fi?.evidenceGap === true && fi.plugin != null && !isPortInputGap(fi)) {
      gaps.set(`${keyHost(fi.host)}|${fi.plugin}`,
        { kind: 'recorded-gap', reason: fi.title ?? fi.detail ?? 'an evidence gap was recorded' });
    }
  }
  // ⚠️ SCOPE STATEMENTS — a producer's own declaration of what it does NOT examine
  // (`details.deferredScope`). Not an exposure and not a gap: set aside here, beside the gaps, so the
  // pairing below never sees them and a reworded boundary cannot read as a fix plus a new finding.
  // A row carrying BOTH flags is a GAP: "could not read" outranks "does not examine".
  const statements = new Map();
  for (const fi of side?.findings ?? []) {
    if (fi?.deferredScope === true && fi?.evidenceGap !== true && fi.plugin != null) {
      const k = `${keyHost(fi.host)}|${fi.plugin}`;
      statements.set(k, [...(statements.get(k) ?? []), fi.title ?? '']);
    }
  }
  // And as the ENGINE records them: a plugin the host never successfully ran.
  for (const h of (Array.isArray(side?.pluginStatus) ? side.pluginStatus : [])) {
    for (const ps of (h?.status ?? [])) {
      if (!NOT_MEASURED_STATUS.has(ps?.status)) continue;
      // ⚠️ A DIFFERENT KIND, AND THE DIFFERENCE IS CLIENT-VISIBLE. Both mean "this surface was not
      // measured", so both belong in the same scope map — but a producer DECLARING a gap
      // (AccessDenied, budget exceeded) and a plugin CRASHING are not the same event, and the
      // first draft of this reported the second with the first's sentence: "the other run
      // recorded an evidence gap … the plugin's status on that host was error". The other run
      // recorded nothing of the sort. That sentence renders into the client's basis cell, which
      // is the surface this whole engine exists to keep honest.
      gaps.set(`${keyHost(h.host)}|${String(ps.id)}`, { kind: 'not-measured',
        reason: `the plugin's status on that host was "${ps.status}"${ps.reason ? `: ${ps.reason}` : ''}` });
    }
  }
  return {
    hosts, hostNames, plugins, gaps, statements,
    // The ports this side could not measure, keyed `hostKey|port` (EE 1.1.0 build 9).
    portGaps: portsNotMeasured(side?.findings),
    // What this side's PORT SCANNER recorded, per host (EE 1.1.0 build 12): present only where 003 RAN and wrote
    // both lists (the loader's `portScan`), so an absent entry means "no oracle", never "nothing open".
    portState: portStateOf(side?.pluginStatus),
    engineLookupGaps: engineLookupGapsOf(side?.findings),
    // Where Enterprise's STAGE did not run on a host (1.1.1): the loader's `eeStage` — a failed LOAD or a failed
    // ENRICHMENT recorded on the host's conclusion — keyed by host.
    eeStages: new Map((Array.isArray(side?.pluginStatus) ? side.pluginStatus : [])
      .filter((h) => h?.eeStage && (h.eeStage.loadError || h.eeStage.enrichmentError)).map((h) => [hostKey(h.host), h.eeStage])),
    // The release that WROTE this side. Carried on the scope because the identity-basis
    // declaration is a property of the comparison — which releases the two runs straddle — and
    // `incomparabilityReason` sees only the two scopes.
    eeVersion: rec.eeVersion ?? null,
    // Where this run's vulnerability data came from (1.2.0 build 2) — the run record's `nvdCache`, rendered in words.
    nvdCache: rec.nvdCache ?? null,
    // ⚠️ WHAT THE RUN ACTUALLY COVERED, per provider — never the FLAG. `undefined` means the
    // record predates this field and the scope is UNKNOWN, which is not the same as "covered
    // nothing": the rule below fails closed on unknown and stays silent when BOTH sides are
    // unknown, because every record written before this change lacks it.
    scopeScanned: rec.scopeScanned
      ? Object.fromEntries(Object.entries(rec.scopeScanned).map(([h, v]) => [hostKey(h), v]))
      : null,
    // ⚠️ AN ABSENT ORACLE IS NOT A CLEAN ONE. `[]` means "measured, no gaps"; MISSING means
    // nothing was measured, and the two must not render alike. Declared in `limits`, never
    // absorbed here — gate:cascade's LEG (ii) is this repo's precedent for the distinction.
    // ⚠️ THIS READ `Array.isArray(side?.pluginStatus)` UNTIL THE OUTCOME CENSUS DROVE IT. Through
    // the shipped path `side.pluginStatus` is `model.plugins.byHost`, which the loader ALWAYS
    // builds — so the test was always true, `scope-not-evaluated` was dead, and a run that
    // recorded no per-host plugin status rendered identically to one that recorded a clean
    // status. That is the exact false clean the comment above forbids, living inside the guard
    // written to prevent it. The loader now carries `pluginStatusRecorded` beside the defaulted
    // array, and this asks the question the comment always meant.
    evaluable: Array.isArray(side?.pluginStatus)
      && side.pluginStatus.every((h) => h?.pluginStatusRecorded !== false),
    frameworks: side?.frameworkEnumeration ?? null,
  };
};

export const SCOPE_NOT_EVALUATED =
  'Scope non-evaluation: one of the two runs recorded no per-host plugin status, so evidence gaps '
  + 'and failed plugins could NOT be distinguished from a clean scan on that side. A finding '
  + 'reported as resolved here may instead be one the scanner could not read. Re-run the '
  + 'comparison against a run recorded by this release or later before treating any row as remediation.';

// ⚠️ THE SECOND HALF WAS ADDED BECAUSE FOUR DECLARED ABSENCES POINT AT THIS SENTENCE AND IT SAID
// NOTHING ABOUT THEM. `contentDigest`, `identityQualifier`, `resource` and `region` are all absent
// on the queue path and each is excused HERE — but the text disclosed only how an agent's SCOPE is
// derived, while what those absences change is IDENTITY. A carve-out is disclosed only if the
// sentence a reader actually meets is the sentence that discloses it.
//
// The consequence is not theoretical: on a real 192.168.1.1 record, TWENTY CVE rows share host,
// port, protocol, service, program and version — `53/udp/dns`, `dnsmasq 2.78` — and are separated
// by their titles alone (20 rows, 20 distinct titles, derived; a first count of 21 was mine and
// was wrong). With no digest on this path, one edit to that title template collapses all twenty
// into a single identity, and IDENTITY_COLLAPSE is the only thing that would say so — after the
// fact. The 1.1.1 repair must hash STABLE content (for a CVE row, `evidence.cve[]` sorted plus
// the service key) and NEVER `description`, which carries the program name identity is moving
// away from — a digest over volatile prose reintroduces the volatility through the digest.
export const AGENT_SCOPE_FROM_TIER =
  'Agent-produced findings: their scope is derived from the run TIER, plus the records a run writes when '
  + 'Enterprise failed on a host, an agent did not run, or a requested plugin it reads did not complete — the '
  + 'agent set is a function of the licensed capabilities, and a tier difference refuses the comparison outright '
  + 'rather than narrowing it. What is NOT compared is whether the plugins an analysis agent or the CVE mapper '
  + 'reads were REQUESTED in both runs: when the two runs requested different --plugins, such a row can read '
  + 'resolved or new with nothing changed. Keep --plugins identical between compared runs. '
  + 'Their IDENTITY is also narrower than a plugin finding\'s: an agent finding is keyed on host, '
  + 'producer, port and title, and on nothing else — it carries no object (resource), no region, '
  + 'no rule qualifier and NO CONTENT DIGEST. So two agent findings that differ only in text the '
  + 'title does not carry share one identity, and one of them can be masked by the other; where '
  + 'that happens it is named individually under the identity-collapse limit.';

// The producer as a READER should see it. `plugin` is an id because that is the vocabulary the
// run record can be checked against; the id alone is not a sentence, and this string is rendered
// into the client's report. Both are printed when they differ, so the prose is readable AND the
// token matches the baseline scope line, which prints `pluginsRequested` — ids.
const producerLabel = (f) => (f.pluginName && f.pluginName !== f.plugin ? `${f.pluginName} (${f.plugin})` : String(f.plugin));

/**
 * THE NOUN FOR A PRODUCER, KEYED ON ITS KIND AND NEVER ON ITS NAME.
 *
 * ⚠️ EXPORTED SO IT CAN BE PROVEN, because it CANNOT be driven. A reviewing seat's mutant re-keyed
 * this from `producerKind` to `f.plugin === 'intelligence_engine'` and passed every leg in the
 * declaration suite — with exactly ONE agent in `IDENTITY_BASIS_CHANGED_AT`, no fixture built from
 * the corpus can tell agent-NESS from that one NAME, and the only branch that prints this noun
 * requires a DECLARED producer. So the case that distinguishes the two implementations is not
 * expressible through the shipped path today, and the day a second agent is declared the client
 * cell would quietly call it a plugin. A helper that cannot be driven is exported and tested
 * directly rather than left to be verified by a fixture that cannot reach it.
 */
export const producerNoun = (f) => (f?.producerKind === 'agent' ? 'producer' : 'plugin');

// Why a finding present in ONE run cannot be compared against the other. Order matters only for
// which reason is reported first; each is independently sufficient.
function incomparabilityReason(f, mine, theirs, names) {
  if (!theirs.hosts.has(hostKey(f.host))) return { reason: 'host-not-scanned', detail: `host ${f.host} was not scanned in ${names.theirs}` };
  // ⚠️ A NULL IDENTITY MAY NEVER SATISFY A SCOPE CHECK, and it may never be DESCRIBED as one
  // either. Before this leg a finding with no producer fell into `plugin-not-run` and reported
  // "plugin null did not run in the other run" — a sentence that is false about the run, about a
  // finding whose comparability was never established. The honest verdict names the thing that is
  // missing. It is checked FIRST because every leg below keys on the producer.
  if (f.plugin == null) {
    return { reason: 'producer-unknown',
      detail: `this finding carries no producer identity, so whether it was in scope in ${names.theirs} cannot be established` };
  }
  // ⚠️ THE ORACLE DEPENDS ON THE PRODUCER KIND, and guessing it from the string's SHAPE is what
  // this leg refuses to do. A plugin id is answerable from `pluginsRequested`. An EE analysis
  // agent appears in no such list and never will, so checking it there would bucket every
  // agent-produced finding as `plugin-not-run` for ever — safe, and useless, which is the failure
  // mode this engine was built to avoid on the other axis. Its scope is the run TIER, and the two
  // whole-comparison refusals above (`ee-presence-differs`, `tier-differs`) guarantee that by the
  // time control reaches here both sides carry Enterprise and the SAME tier, so the agent SET is
  // identical on both. ⚠️ THAT DOES NOT MAKE AN AGENT ROW COMPARABLE (1.2.0 limit, boarded for
  // 1.2.1): the agent — and the CVE mapper — derives its rows from other plugins' output, and those
  // can differ at the same tier when `--plugins` was narrowed in one run. Nothing here checks them,
  // so such a row reads resolved or new; AGENT_SCOPE_FROM_TIER says so. That per-finding INPUT check
  // CAN fail through the shipped path — it is owed, not dead code.
  if (f.producerKind !== 'agent' && !theirs.plugins.has(f.plugin)) {
    // ⚠️ THE NOUN HERE IS A LITERAL `plugin` AND THAT IS CORRECT — but only because of the
    // `producerKind !== 'agent'` guard on this very line, which makes the branch unreachable for
    // an agent. Delete that guard and this sentence starts calling agents plugins, which is the
    // defect the identity branch below had to be repaired for. The coupling is written here
    // because a reader deleting the guard is reading THIS line, not the sentence's test.
    return { reason: PLUGIN_NOT_RUN_REASON, detail: `plugin ${producerLabel(f)} did not run in ${names.theirs}` };
  }
  // ⚠️ ENTERPRISE'S STAGE DID NOT RUN ON THIS HOST IN ONE OF THE RUNS (1.1.1 — the audit seat's T1-c ruling). A failed
  // LOAD (utils/ee_load.mjs) or a failed ENRICHMENT leaves the host with no analysis-agent and no CVE-mapper rows, while
  // the run record still names Enterprise's version and the same tier — so the whole-comparison refusals above do not
  // fire, and before this leg every such row the other run held read RESOLVED. A queue-path row (an Enterprise producer)
  // on a host where EITHER run recorded the failure was not looked for there. `evidence-gap`, the reason an individual
  // agent's not-run record already carries; Community's plugins are not affected (their own status governs them).
  // Checked before the identity-basis leg: a stage that did not run is a statement about coverage, and it wins.
  if (f.producerKind === 'agent') {
    const k = hostKey(f.host);
    const stage = theirs.eeStages?.get(k) ?? mine.eeStages?.get(k);
    if (stage) {
      const which = theirs.eeStages?.has(k) ? names.theirs : names.mine;
      const what = stage.loadError ? 'failed to load' : 'failed during enrichment';
      return { reason: 'evidence-gap',
        detail: `Enterprise ${what} on ${f.host} in ${which} — none of its analysis agents or its CVE mapper ran there, so `
          + `this ${producerNoun(f)}'s rows were not looked for (${withoutLocalPaths(stage.loadError ?? stage.enrichmentError).slice(0, 200)})` };
    }
  }
  // ⚠️ THE PRODUCER CHANGED WHAT IT NAMES BETWEEN THESE TWO RELEASES, so its two keys for one
  // object cannot be matched and must not be DIFFERENCED either. Checked here, before the
  // evidence-gap legs, because it is a statement about the COMPARISON rather than about either
  // run's coverage: the surface was read on both sides, and what moved is the noun.
  //
  // It is keyed on the baseline PREDATING the declared change, never on the versions merely
  // differing — the latter would declare on every upgrade for ever and quietly retire the
  // feature. `identityBasisChanged` is one-directional for that reason.
  if (identityBasisChanged(f.plugin, mine.eeVersion, theirs.eeVersion)
    || identityBasisChanged(f.plugin, theirs.eeVersion, mine.eeVersion)) {
    const at = IDENTITY_BASIS_CHANGED_AT[f.plugin];
    return { reason: IDENTITY_BASIS_CHANGED_REASON,
      // ⚠️ "producer" FOR AN AGENT. This sentence renders into the client artifact's basis cell,
      // and it hardcoded "plugin" — harmless while every declared producer WAS one, and false the
      // moment an analysis agent joined the table. It was UNREACHABLE for an agent until that
      // happened, which is why the wording lands in the same commit as the declaration rather
      // than earlier: before this, no test could have driven it. Same class as the
      // "plugin undefined did not run in the other run" detail this engine already had to fix.
      detail: `${producerNoun(f)} ${producerLabel(f)} `
        + `changed what it names as a finding's object at EE ${at}; `
        + 'the two runs straddle that change, so this finding\'s identity is not comparable '
        + 'between them. It is NOT reported as fixed or as new — rescan to compare.' };
  }
  // ⚠️ DID THE OTHER RUN EVEN LOOK THERE? Placed after plugin-not-run and the identity
  // declaration — those are statements about the PRODUCER and the COMPARISON — and before the
  // gap legs, because "the surface was outside the scan's scope" is more precise than "no gap was
  // recorded for it": a region nobody scanned records no gap by construction.
  //
  // ⚠️ MEASURED, NOT HYPOTHETICAL. Two live AWS passes differing only in `--aws-region` reported
  // EIGHT unremediated `eu-west-1` findings as RESOLVED — GuardDuty NOT ENABLED, Inspector2
  // DISABLED, default EBS encryption DISABLED — because narrowing a follow-up scan is a normal
  // operator action and nothing in the record could tell it from remediation.
  const scopeMiss = scopeNotScanned(f, mine, theirs, names);
  if (scopeMiss) return { reason: SCOPE_NOT_SCANNED_REASON, detail: scopeMiss };

  // ⚠️ `theirs` ONLY, AND THE `?? mine.gaps` THAT USED TO SIT HERE WAS WRONG IN BOTH HALVES.
  // A gap says "this run could not read that surface", so it explains what a run is MISSING —
  // never what a run is HOLDING. This lookup only ever runs for an UNMATCHED finding, and in both
  // directions `theirs` is the side that failed to look: for a row that vanished, the other run is
  // where it should have reappeared; for a row that appeared, the other run is where it should
  // already have been. `mine` is never the side that failed to look at a finding my own run is
  // holding in its hand.
  //
  // ⚠️ IT WAS UNREACHABLE, WHICH IS WHY IT SHIPPED — and EE 1.1.0's widened mapper boundary made
  // it live on ordinary pairs. Before, the `mine` half needed a gap on the finding's own side
  // beside a bucketed row from the SAME producer, and no shipped producer made that pair. Now both
  // sides of any degraded network comparison carry the mapper's gap. Driven before this fix: a
  // genuinely NEW row on the degraded side, against a full baseline that recorded no gap at all,
  // came back `new = 0` and `not-comparable · evidence-gap` — a suppressed new exposure, explained
  // by the detail below, which says "the OTHER run recorded an evidence gap" and was false about
  // the baseline. Narrowing to `theirs` is what makes that sentence unconditionally true.
  const gap = theirs.gaps.get(`${hostKey(f.host)}|${f.plugin}`);
  if (gap) {
    return gap.kind === 'recorded-gap'
      ? { reason: 'evidence-gap',
        detail: `${names.theirs} recorded an evidence gap on ${f.host}/${producerLabel(f)}: ${gap.reason}` }
      : { reason: PLUGIN_NOT_MEASURED_REASON,
        detail: `${f.host}/${producerLabel(f)} was not measured in ${names.theirs} — ${gap.reason}` };
  }
  // ⚠️ THE FINDING'S PORT WAS NOT MEASURED IN THE OTHER RUN (EE 1.1.0 build 9, F6). Any producer's row: a
  // probe that could not complete on an OPEN port starves every consumer of that port's service. Placed
  // AFTER the producer-wide legs, so a verdict they already give does not move. `theirs` only, as above.
  const portGap = f.port != null && Number(f.port) > 0 ? theirs.portGaps?.get(portGapKey(f.host, f.port)) : null;
  if (portGap) {
    return { reason: PROBE_NOT_MEASURED_REASON,
      detail: `port ${f.port} on ${f.host} was not measured in ${names.theirs} — a probe ran there and did not `
        + `complete its connection (${portGap}). It is NOT reported as fixed or as new — rescan to compare.` };
  }
  // ⚠️ THE CVE MAPPER COULD NOT LOOK THIS SERVICE UP IN THE OTHER RUN (1.1.1, T1b). Its own lookup gap on the same
  // (host, port, transport) says the CVE rows were not looked for, whatever the port's state — so it answers before
  // the port rules, and before the UDP exemption, whose "answered and identified" cannot say the lookup worked.
  // ⚠️ AND A LOOKUP-GAP ROW ON ONE SIDE ONLY IS ITSELF NEVER NEW OR RESOLVED (condition 4): it is a record that the
  // mapper could not look a service up, so its appearing is not a new exposure and its vanishing is not a remediation
  // (the lookup worked again, or the service changed). It stays visible, with its reason, rather than leaving the table.
  if (isEngineLookupGap(f)) {
    return { reason: 'evidence-gap',
      detail: `this is the CVE mapper's own record that it could not look up the service on ${f.port}/`
        + `${TRANSPORT_OF_LABEL[String(f.protocol ?? '').toLowerCase()] ?? f.protocol} (${f.gapClass}), present in only one of the `
        + 'two runs — a coverage gap that opened or cleared, not an exposure that appeared or was fixed.' };
  }
  if (f.plugin === CVE_MAPPER_PRODUCER && Number(f.port) > 0) {
    const lookupGap = theirs.engineLookupGaps?.get(engineLookupGapKey(f.host, f.port, f.protocol));
    if (lookupGap) {
      return { reason: 'evidence-gap',
        detail: `the CVE mapper recorded in ${names.theirs} that it could not look up the service on ${f.port}/`
          + `${TRANSPORT_OF_LABEL[String(f.protocol ?? '').toLowerCase()] ?? f.protocol} on ${f.host} (${lookupGap}), so its CVE `
          + 'rows there were not looked for. It is NOT reported as fixed or as new — rescan once the lookup succeeds.' };
    }
  }
  // ⚠️ THE FINDING'S PORT STOPPED ANSWERING (EE 1.1.0 build 12). Open in the run that HOLDS the finding, and in the
  // other run the port scanner ran and put it in NEITHER list: no answer inside its timeout, or not probed. After
  // F6, so a probe-not-measured verdict does not move. Keyed on the HOLDING run's tcpOpen, so a UDP service or a
  // port no TCP list ever named is untouched; and only where the other run's scanner RAN on this host — with no
  // oracle there the rule is silent and the legs above govern (a stated limit, not an inference).
  //
  // ⚠️ GATED TO NON-UDP ROWS (1.1.1): the port scanner's lists are TCP, and a udp/53 row judged by TCP/53 read
  // RESOLVED when TCP/53 closed and printed this TCP-only sentence when TCP/53 was filtered. A UDP-transport row goes
  // to the leg below whatever TCP says about its port number.
  const port = Number(f.port);
  const udpRow = isUdpTransport(f.protocol);
  if (port > 0 && !udpRow) {
    const held = mine.portState?.get(hostKey(f.host));
    const other = theirs.portState?.get(hostKey(f.host));
    // `other?.open` — the TCP ORACLE, present only where 003 ran; a host entry may carry the UDP oracle alone (1.1.1).
    if (held?.open?.has(port) && other?.open && other?.closed && !other.open.has(port) && !other.closed.has(port)) {
      return { reason: PORT_NOT_MEASURED_REASON,
        detail: `port ${port} on ${f.host} was open in ${names.mine}, and ${names.theirs}'s port `
          + 'scanner recorded it neither open nor closed — no answer inside its timeout (filtered), or not probed — so '
          + 'the port was not measured there. It is NOT reported as fixed or as new — rescan to compare. (This rule '
          + 'reads TCP ports the port scanner saw open; a UDP-transport finding is judged by its own rule, and a '
          + 'host-wide finding by neither.)' };
    }
  }
  // ⚠️ A UDP-TRANSPORT ROW PRESENT IN ONE RUN ONLY (1.1.1). No UDP producer in this release records a port as
  // CLOSED, so the other run's silence on this port is not a measurement: never RESOLVED, never NEW. Its precondition
  // is the finding's PRODUCER having run in the other run, which the producer-wide legs above already own — a gap or
  // a not-measured producer answers first. It never reads the port scanner, so it does not depend on 003 running.
  // ⚠️ THE ORACLE IS THE OTHER RUN'S UDP SERVICE RECORD (`udpPortMeasurement`, shared with MTTR): where it says the
  // port was measured for this producer the verdict stands — a changed SNMP community resolves, a dnsmasq version
  // bump moves its CVE set; everywhere else the row is not comparable, and the detail names which absence it was.
  // With no service set recorded the rule FIRES: a UDP row with no oracle has no measurement at all (deliberately
  // unlike the TCP rule's silence without 003). A PORTLESS UDP row (mdns/0) stays outside, as a host-wide row does.
  if (port > 0 && udpRow) {
    const m = udpPortMeasurement(port, f.plugin, theirs.portState?.get(hostKey(f.host))?.udpServices ?? null, names.theirs);
    if (!m.measured) {
      // The explanation follows the BRANCH: a service that answered but was not identified was not silent (the verifier
      // of the first draft found it told the reader both), and rescanning will not change it while its version is hidden.
      const why = m.kind === 'unidentified'
        ? 'An unidentified service gives the CVE mapper nothing to match, so the absence of a CVE row there is not a '
          + 'measurement. It is NOT reported as fixed or as new — rescan once the service\'s version can be read.'
        : 'UDP silence is not a measurement: no producer in this release records an unanswered UDP port as closed, so a '
          + 'UDP service that stopped answering cannot be told apart from one that was fixed. It is NOT reported as fixed '
          + 'or as new — rescan, and confirm the service directly.';
      return { reason: PORT_NOT_MEASURED_REASON,
        detail: `${port}/udp on ${f.host} (${f.protocol}) carries a finding in only one of the two runs, and ${m.why}. ${why}` };
    }
  }
  // ⚠️ THE SAME PROGRAM AND VERSION ANSWERED IN BOTH RUNS, AND ONE OF THEM HOLDS A CVE ROW THE OTHER DOES NOT (1.2.0
  // build 2). DISAPPEARED only: a newly attributed CVE is new knowledge about an exposure that is real now, so it stays
  // NEW and carries a basis note instead (`withNewBasis`). After the port and UDP legs, so a port that was not measured
  // keeps its own reason; the mapper's CVE rows only — its gap and note rows carry a `gapClass` and are not attributions.
  if (f.plugin === CVE_MAPPER_PRODUCER && !f.gapClass && port > 0 && names.mine === RUN_NAMES.baseline) {
    const was = serviceIdentityAt(mine.portState?.get(hostKey(f.host))?.services, port, f.protocol);
    const now = serviceIdentityAt(theirs.portState?.get(hostKey(f.host))?.services, port, f.protocol);
    if (sameServiceIdentity(was, now)) {
      return { reason: VULNERABILITY_DATA_CHANGED_REASON,
        detail: `the same ${now.program} ${now.version} answered on ${port}/${now.transport} on ${f.host} in both runs, and `
          + 'the CVE mapper attributes a CVE on the program and version alone — so this row\'s absence is a change in the '
          + 'vulnerability data it was matched against, not a remediation. Vulnerability data — '
          + `${names.mine}: ${vulnerabilityDataSource(mine.nvdCache)}; ${names.theirs}: ${vulnerabilityDataSource(theirs.nvdCache)}. `
          + 'It is NOT reported as fixed — confirm against the vendor\'s advisory.' };
    }
  }
  // ⚠️ NO SILENT SHORT-CIRCUIT. This used to read `mine.frameworks && theirs.frameworks &&
  // f.control`, and all three are absent through the shipped path — so the leg returned null and
  // the finding fell through to `resolved`. That is FAIL-OPEN, the opposite of the `plugin` gap:
  // a finding whose control stopped being enumerated read as REMEDIATED in a client artifact.
  // Whether the oracle exists is now decided ONCE, by `frameworkEnumerationEvaluable`, and its
  // absence is DECLARED in `limits` rather than absorbed here.
  if (frameworkEnumerationEvaluable(mine, theirs) && f.control) {
    const inMine = mine.frameworks.includes(f.control);
    const inTheirs = theirs.frameworks.includes(f.control);
    if (inMine !== inTheirs) {
      return { reason: 'framework-enumeration-changed', detail: `control ${f.control} is enumerated in only one of the two runs` };
    }
  }
  return null;
}

// ── THE CVE MAPPER'S OWN LOOKUP GAPS, PORT-SCOPED (1.1.1, T1b) ────────────────────────────────────────────────────
// Enterprise's intelligence engine records a service it could not look up — the NVD lookup failed, the response was
// not an array, the offline store could not be read or held no entry for the CPE, the program has no CPE alias, the
// banner carried no version — as `[COVERAGE GAP] <gapClass> — <protocol>/<service>` with a `gapClass` and NO
// `evidenceGap` flag. So since 0.2.55 a failed lookup made the baseline's CVE rows on that service read RESOLVED (TCP
// and UDP alike). Flagging the record `evidenceGap` would not do: the recorded-gap leg keys PRODUCER-wide, so one
// cpe_map_miss — every run has some — would set aside every engine row on the host. So it is PORT-SCOPED, on
// (host, port, transport) from the gap record's own target, and it applies to the CVE mapper's rows alone. The gap
// rows stay paired like findings (unchanged across runs); one on a single side is refused, never NEW or RESOLVED.
//
// ⚠️ THE TABLE CLASSIFIES EVERY GAP CLASS THE ENGINE DECLARES, and Enterprise's test holds it in two-way equality with
// the engine's GAP_CLASSES, so a class the engine adds and nobody classified fails the build — incompleteness costs
// noise, never silence. `offline_store_no_match` is a lookup failure too: a CPE absent from the store is
// indistinguishable from an incomplete store, and a baseline that HAD rows for that CPE means the store moved.
export const ENGINE_GAP_CLASS_KIND = Object.freeze({
  nvd_lookup_failure: 'lookup-failed',
  nvd_response_not_array: 'lookup-failed',
  offline_store_read_error: 'lookup-failed',
  offline_store_no_match: 'lookup-failed',
  cpe_map_miss: 'lookup-failed',
  no_version_detected: 'lookup-failed',
  truncated_low_severity_cves: 'note',      // a COVERAGE NOTE: the lookup worked and some LOW rows were folded
  input_gap: 'input-gap',                   // the engine's input gap — an evidence gap, handled by the recorded-gap leg
});
/** A CVE-mapper lookup-gap row, port-scoped. Written as plain `f.` reads so the boundary contract sees them. */
export const isEngineLookupGap = (f) => f != null && f.plugin === CVE_MAPPER_PRODUCER
  && ENGINE_GAP_CLASS_KIND[f.gapClass] === 'lookup-failed' && Number(f.port) > 0;
/** The key a lookup gap and the CVE rows it covers share: host (as `hostKey`), port, and the TRANSPORT of the label. */
export const engineLookupGapKey = (host, port, protocol) =>
  `${hostKey(host)}|${Number(port)}|${TRANSPORT_OF_LABEL[String(protocol ?? '').toLowerCase()] ?? `label:${String(protocol ?? '').toLowerCase()}`}`;
function engineLookupGapsOf(findings) {
  const out = new Map();
  for (const f of Array.isArray(findings) ? findings : []) {
    if (isEngineLookupGap(f)) out.set(engineLookupGapKey(f.host, f.port, f.protocol), f.gapClass);
  }
  return out;
}

// A UDP row that RESOLVED or APPEARED did so because the other run MEASURED its port (1.1.1) — so the row shows that
// work, in the client's own report: the Pro page sells a resolved column that says why it was trusted. `basisNote` is
// output-only; nothing here reads it back.
function withUdpBasis(f, theirs, theirName) {
  const port = Number(f.port);
  if (!(port > 0) || !isUdpTransport(f.protocol)) return f;
  const m = udpPortMeasurement(port, f.plugin, theirs.portState?.get(hostKey(f.host))?.udpServices ?? null, theirName);
  return m.measured ? { ...f, basisNote: m.basis } : f;
}

// A CVE row that APPEARED on a service identified the same in both runs (1.2.0 build 2 — MANDATORY, the audit seat's
// ruling): it stays NEW, and says the service did not change, because "new exposure on my estate" and "new knowledge
// about an old service" route to different work. A changed or unidentified service keeps today's basis.
function withNewBasis(f, mine, theirs) {
  const port = Number(f.port);
  if (f.plugin === CVE_MAPPER_PRODUCER && !f.gapClass && port > 0) {
    const now = serviceIdentityAt(mine.portState?.get(hostKey(f.host))?.services, port, f.protocol);
    const was = serviceIdentityAt(theirs.portState?.get(hostKey(f.host))?.services, port, f.protocol);
    if (sameServiceIdentity(was, now)) {
      return { ...f, basisNote: `newly attributed — the same ${was.program} ${was.version} answered on ${port}/${was.transport} `
        + `in ${RUN_NAMES.baseline}; the service is unchanged, the vulnerability data is not` };
    }
  }
  return withUdpBasis(f, theirs, RUN_NAMES.baseline);
}

// The oracle test, separated from the per-finding check so its ABSENCE has somewhere to be
// declared. gate:cascade's LEG (ii) is the precedent this repo already set: when the oracle is
// missing, print NOT EVALUATED and never pass silently.
export const FRAMEWORK_MOVEMENT_NOT_EVALUATED =
  'Coverage-matrix movement between the two runs was NOT EVALUATED: this edition records no '
  + 'framework enumeration on a run, so if a control stopped being enumerated between the two '
  + 'scans, findings that mapped to it may appear as resolved here. Compare the two runs\' '
  + 'framework coverage separately before treating any row as remediation.';

export const BASELINE_UNCHAINED =
  'The baseline carries no integrity digest (it predates chained run records), so alteration of '
  + 'the baseline could not be ruled out.';

export const EVIDENCE_GAPS_RECORDED =
  'One or more EVIDENCE GAPS were recorded. A gap is a surface the scanner could not read, not a '
  + 'finding: gaps are listed under coverage, and any finding a gap covers is reported as '
  + 'not-comparable rather than as resolved.';

// The stable head of the collision limit; the colliding identities are appended at the call site.
export const IDENTITY_COLLAPSE =
  'Two or more findings collapsed to one identity (same host, plugin, resource, port, rule '
  + 'qualifier and content). Appearance and disappearance of individual instances cannot be '
  + 'distinguished, so A NEW FINDING MAY BE MASKED by a surviving one that shares its identity. '
  + 'Colliding identities: ';

// ⚠️ THESE TWO ARE EMITTED BY `scan_delta_view.mjs`, AND THEY LIVE HERE ANYWAY. The vocabulary is
// one module or it is two copies: the view imports them. Declaring them beside the view that
// pushes them would put half the census's subject outside the export the census reads.
export const CURRENT_UNCHAINED =
  'The current run carries no integrity digest (it predates chained run records), so alteration '
  + 'of the run being reported could not be ruled out.';

export const CURRENT_CHAIN_LINK_BROKEN =
  'The current run record names a predecessor whose bytes no longer exist (the record was deleted '
  + 'or rewritten). The baseline used here was named explicitly, so it is the one that was asked '
  + 'for \u2014 but the run chain covering this comparison is incomplete.';


// ────────────────────────────────────────────────────────────────────────────────────────────
// THE OUTCOME VOCABULARY — ONE EXPORT, READ BY THE CENSUS, COPIED NOWHERE.
//
// ⚠️ WHY THIS EXISTS: a guard can be disarmed by a FIX THAT NARROWS ITS SUBJECT, with nothing
// failing and nobody editing the guard. It happened twice in two commits in this lane. The census
// (`tests/delta_outcome_census.test.mjs`) asserts SET EQUALITY between what is declared here and
// what the SHIPPED entry point actually produces, so a narrowed trigger fails BY NAME. A new
// outcome joins the census by being written here — incompleteness costs NOISE, never silence.
// ⚠️ APPEND-ONLY under `SCAN_DELTA_SCHEMA = 1`, exactly as the reason codes are.
// ────────────────────────────────────────────────────────────────────────────────────────────

// How much of a limit's sentence identifies it. A limit has no short code in its own text, so the
// census probes its HEAD; the self-check refuses two limits whose heads collide.
export const OUTCOME_PROBE_CHARS = 48;

export const DECLARED_LIMITS = Object.freeze({
  'baseline-unchained': BASELINE_UNCHAINED,
  'chain-assurance': CHAIN_ASSURANCE_LABEL,
  'framework-movement-not-evaluated': FRAMEWORK_MOVEMENT_NOT_EVALUATED,
  'scope-not-evaluated': SCOPE_NOT_EVALUATED,
  'evidence-gaps-recorded': EVIDENCE_GAPS_RECORDED,
  'agent-scope-from-tier': AGENT_SCOPE_FROM_TIER,
  'identity-collapse': IDENTITY_COLLAPSE,
  'current-unchained': CURRENT_UNCHAINED,
  'current-chain-link-broken': CURRENT_CHAIN_LINK_BROKEN,
});

const outcome = (species, probe) => Object.freeze({ species, probe });
export const DECLARED_OUTCOMES = Object.freeze({
  ...Object.fromEntries(NOT_COMPARABLE_REASONS.map((c) => [c, outcome('not-comparable', c)])),
  ...Object.fromEntries([...REFUSAL_REASONS, ...VIEW_REFUSAL_REASONS]
    .map((c) => [c, outcome('refusal', c)])),
  ...Object.fromEntries(Object.entries(DECLARED_LIMITS)
    .map(([c, text]) => [c, outcome('limit', text.slice(0, OUTCOME_PROBE_CHARS))])),
});

// ⚠️ NOT A WAIVER, AND NOT A BARE ALLOWLIST. Each member names the limit that DISCLOSES its
// absence, and the census verifies that limit is actually produced — the same premise-checking
// discipline as `DECLARED_ABSENT_FINDING_FIELDS` above, for the same reason: a carve-out whose
// premise nobody re-checks is how an absence becomes a silent pass.
export const DECLARED_UNREACHABLE_OUTCOMES = Object.freeze({
  'run-record-schema-differs': {
    reason: 'An EARLIER layer refuses first and this branch cannot be reached. `loadRun` pins the '
      + 'run-record schema to the one this build understands and refuses any other outright, so two '
      + 'records that both LOAD always agree on schema. The guard stays because it is the library '
      + 'contract for a caller that builds a delta without the loader.',
    instead: 'this build understands schema',
  },
  'framework-enumeration-changed': {
    reason: 'Reaching this needs a framework enumeration on BOTH runs and a `control` on a finding. '
      + 'Community ships no compliance data, `report_inputs.mjs` emits no control id, and '
      + '`scan_delta_view.mjs` passes no frameworkEnumeration to buildScanDelta — so no CE run can '
      + 'produce it. It stays declared because EE routing supplies exactly these inputs, and the '
      + 'engine must refuse rather than report a de-enumerated control as remediated.',
    disclosedBy: 'framework-movement-not-evaluated',
  },
});

function frameworkEnumerationEvaluable(mine, theirs) {
  return Boolean(mine?.frameworks && theirs?.frameworks);
}

// Hosts are SHOWN as recorded: the maps are keyed by `hostKey`, and `hostNames` carries the spelling.
const shownHost = (scope, k) => scope.hostNames?.get(k) ?? k;

const statementList = (scope) => [...scope.statements.entries()].flatMap(([k, titles]) => {
  const i = k.indexOf('|');
  return titles.map((title) => ({ host: shownHost(scope, k.slice(0, i)), plugin: k.slice(i + 1), title }));
});

const gapList = (scope) => [...scope.gaps.entries()].map(([k, g]) => {
  const i = k.indexOf('|');
  return { host: shownHost(scope, k.slice(0, i)), plugin: k.slice(i + 1), kind: g.kind, reason: g.reason };
});

export function buildScanDelta({ baseline, current }) {
  const limits = [];
  const refuse = (reason, detail) => ({
    schema: SCAN_DELTA_SCHEMA, comparable: false, refusal: { reason, detail },
    newFindings: [], resolved: [], unchanged: [], changed: [], notComparable: [],
    baselineIntegrity: null, currentIntegrity: null, limits: [detail],
  });

  // ── Whole-comparison refusals. Each is a case where NO per-finding verdict is trustworthy.
  const bEE = baseline?.record?.eeVersion ?? null;
  const cEE = current?.record?.eeVersion ?? null;
  if ((bEE === null) !== (cEE === null)) {
    return refuse('ee-presence-differs',
      'one run carries Enterprise findings and the other does not, so the two populations are not the same population');
  }
  if (bEE && cEE) {
    const bPre = cmpVersion(bEE, FINDING_COUNT_BOUNDARY_EE) <= 0;
    const cPre = cmpVersion(cEE, FINDING_COUNT_BOUNDARY_EE) <= 0;
    if (bPre !== cPre) {
      return refuse('finding-count-semantics-boundary',
        `EE ${bEE} and EE ${cEE} sit on opposite sides of the ${FINDING_COUNT_BOUNDARY_EE} findingCount semantics boundary ` +
        '(contract-v1 §5.3): before it the key carried the ISSUE count, so a comparison across it shows a fall that is a ' +
        'correction and not remediation');
    }
  }
  // ⚠️ TIER IS A STATEMENT ABOUT THE PRODUCER POPULATION, not about how much detail a report
  // shows. `agents/agent_runner.mjs` runs the agents the run's CAPABILITIES license, so an
  // enterprise baseline compared against a pro current is missing an entire producer — and every
  // finding that producer found would read as REMEDIATION. This refuses rather than annotating,
  // for the same reason `ee-presence-differs` does: the two populations are not the same
  // population, and no per-finding verdict across them is trustworthy.
  const bTier = baseline?.record?.tier ?? null;
  const cTier = current?.record?.tier ?? null;
  if (bTier !== cTier) {
    return refuse('tier-differs',
      `the baseline ran at tier "${bTier}" and the current run at tier "${cTier}": the licensed `
      + 'producer set differs between them, so findings absent from the narrower run may simply '
      + 'never have been looked for');
  }
  if ((baseline?.record?.schema ?? null) !== (current?.record?.schema ?? null)) {
    return refuse('run-record-schema-differs',
      `run record schema ${baseline?.record?.schema} vs ${current?.record?.schema}: the two records do not describe coverage the same way`);
  }

  // ── Baseline integrity. A broken chain means the baseline on disk is not the baseline that was
  // written, so every verdict derived from it is unsound — refuse rather than annotate.
  const baselineIntegrity = baseline?.integrity ?? 'chain-absent';
  // ⚠️ THE CURRENT RUN IS ALTERABLE TOO, and until T3 nothing could verify it. A basis that names
  // only the baseline describes half the evidence the verdict rests on. Unlike the baseline this
  // one is never a refusal HERE — the view refuses on it before the engine is called, because the
  // engine is deliberately filesystem-free and integrity is a fact about bytes on disk.
  const currentIntegrity = current?.integrity ?? null;
  if (baselineIntegrity === 'chain-broken') {
    return refuse('baseline-chain-broken',
      'the baseline run record does not match its recorded digest: it was altered, truncated or partially restored after the run');
  }
  // ⚠️ COULD-NOT-MEASURE IS NEVER A PASS. `chain-unreadable` is not `chain-absent`: absent means
  // the record predates chaining and we know that; unreadable means the instrument failed and we
  // know nothing. Letting the second one through would be a verdict from a run that measured nothing.
  if (baselineIntegrity === 'chain-unreadable') {
    return refuse('baseline-integrity-unmeasurable',
      'the baseline integrity digest could not be read, so alteration of the baseline could neither be confirmed nor ruled out');
  }
  if (baselineIntegrity === 'chain-absent') {
    limits.push(BASELINE_UNCHAINED);
  }
  limits.push(CHAIN_ASSURANCE_LABEL);
  // Declared once for the whole comparison, not per finding: it is a property of the two RUNS.
  if (!frameworkEnumerationEvaluable(scopeOf(baseline), scopeOf(current))) {
    limits.push(FRAMEWORK_MOVEMENT_NOT_EVALUATED);
  }

  const bScope = scopeOf(baseline);
  const cScope = scopeOf(current);
  if (!bScope.evaluable || !cScope.evaluable) limits.push(SCOPE_NOT_EVALUATED);

  // ⚠️ A GAP RECORD IS SCOPE AND MUST NOT BE BUCKETED AS A FINDING. It has a severity, a title and
  // — since the producer identity landed — a plugin, so it is comparable like anything else and
  // would otherwise arrive in the client's NEW EXPOSURES table as an INFO row reading
  // "Evidence gap (…)". It has already been read INTO `scopeOf` above, which is its whole job:
  // it explains why its neighbours are not comparable. Measured before the exclusion: the
  // `gap-leg` scenario read `1 new · 1 resolved` where the honest answer is `0 new · 0 resolved`.
  const isGap = (f) => f.evidenceGap === true;
  // A declared scope boundary is set aside the same way (read into `scopeOf` as a statement); a row
  // flagged as both is a gap, which the line above already removes.
  const isScopeStatement = (f) => f.deferredScope === true;
  // (The CVE mapper's lookup-gap rows stay PAIRED — unchanged when both runs carry one, which the mapper-gap corpus
  // leg pins — and one present on ONE side only is refused in `incomparabilityReason`, never NEW or RESOLVED.)
  const bFind = (baseline?.findings ?? []).filter((f) => !isGap(f) && !isScopeStatement(f));
  const cFind = (current?.findings ?? []).filter((f) => !isGap(f) && !isScopeStatement(f));
  if ((baseline?.findings ?? []).some(isGap) || (current?.findings ?? []).some(isGap)) {
    // ⚠️ THE WORDING AVOIDS THE LITERAL BUCKET NAME ON PURPOSE. `scripts/board_probe_delta_driver.mjs`
    // harvests reasons by matching that phrase against every output line, so a LIMIT containing it
    // is read back as if it were a per-finding reason — an instrument the next seat reads,
    // reporting a bucket that no finding is in.
    limits.push(EVIDENCE_GAPS_RECORDED);
  }
  if ((baseline?.findings ?? []).some((f) => f.producerKind === 'agent')
    || (current?.findings ?? []).some((f) => f.producerKind === 'agent')) {
    limits.push(AGENT_SCOPE_FROM_TIER);
  }
  const bMap = new Map(bFind.map((f) => [keyOf(f), f]));
  const cMap = new Map(cFind.map((f) => [keyOf(f), f]));
  // ⚠️ THE LIMIT NAMES THE DIRECTION, because the previous wording ("per-instance deltas are not
  // distinguished") read as a granularity note when the real consequence is a missing exposure.
  if (bMap.size !== bFind.length || cMap.size !== cFind.length) {
    // ⚠️ THE LIMIT NAMES EACH COLLIDING IDENTITY. A generic disclosure tells a reader that SOME
    // finding may be masked and gives them nothing to act on; the whole point is that they can go
    // and look at the one that collided.
    const collide = [];
    for (const [side, list] of [['baseline', bFind], ['current', cFind]]) {
      const seen = new Map();
      for (const f of list) {
        const k = keyOf(f);
        seen.set(k, (seen.get(k) ?? 0) + 1);
      }
      for (const f of list) {
        const k = keyOf(f);
        if ((seen.get(k) ?? 0) > 1 && !collide.some((c) => c.k === k)) {
          // ⚠️ THE REGION IS NAMED WHEN THERE IS NO RESOURCE (board E1). This limit exists so a
          // reader can ACT on a collision, which means it has to say WHICH object collided. The
          // population that collides most is the one whose producer emits no resource at all —
          // and before E1 those findings borrowed the REGION as their resource, so the limit
          // read `us-east-1` and looked actionable. E1 correctly stops that borrowing, which
          // would have left this limit saying `no resource` and nothing else. The region is a
          // field now, so it is named as what it is rather than impersonating an object id.
          const where = f.resource ?? (f.region ? `no resource · region ${f.region}` : 'no resource');
          collide.push({ k, text: `${side}: plugin ${f.plugin} · ${where} · `
            + `"${String(f.title ?? '').slice(0, 80)}" ×${seen.get(k)}` });
        }
      }
    }
    limits.push(IDENTITY_COLLAPSE + collide.map((c) => c.text).join(' | '));
  }

  const resolved = [];
  const newFindings = [];
  const unchanged = [];
  const changed = [];
  const notComparable = [];

  for (const [k, f] of bMap) {
    if (cMap.has(k)) {
      // Matched on identity — so a severity move is the SAME finding getting worse or better,
      // which is the trend report's actual deliverable. Never a resolution plus a new finding.
      const now = cMap.get(k);
      if ((f.severity ?? null) !== (now.severity ?? null)) changed.push({ ...now, from: f.severity ?? null, to: now.severity ?? null });
      else unchanged.push(f);
      continue;
    }
    const why = incomparabilityReason(f, bScope, cScope, FRAME_DISAPPEARED);
    if (why) notComparable.push({ ...f, direction: 'disappeared', ...why });
    else resolved.push(withUdpBasis(f, cScope, RUN_NAMES.current));
  }
  for (const [k, f] of cMap) {
    if (bMap.has(k)) continue;
    // The mirror, and it is not symmetric in danger: a finding "new" only because its host or
    // plugin was out of scope last time is NEW COVERAGE, not a new exposure.
    const why = incomparabilityReason(f, cScope, bScope, FRAME_APPEARED);
    if (why) notComparable.push({ ...f, direction: 'appeared', ...why });
    else newFindings.push(withNewBasis(f, cScope, bScope));
  }

  return {
    schema: SCAN_DELTA_SCHEMA, comparable: true, refusal: null,
    newFindings, resolved, unchanged, changed, notComparable,
    baselineIntegrity, currentIntegrity, limits,
    coverage: {
      hostsOnlyInBaseline: [...bScope.hosts].filter((h) => !cScope.hosts.has(h)).map((h) => shownHost(bScope, h)),
      hostsOnlyInCurrent: [...cScope.hosts].filter((h) => !bScope.hosts.has(h)).map((h) => shownHost(cScope, h)),
      pluginsOnlyInBaseline: [...bScope.plugins].filter((p) => !cScope.plugins.has(p)),
      pluginsOnlyInCurrent: [...cScope.plugins].filter((p) => !bScope.plugins.has(p)),
      // The gaps themselves, named. A reader who sees a NOT-COMPARABLE row needs to be able to
      // find out WHICH surface was unreadable without reading the raw envelope.
      gapsInBaseline: gapList(bScope),
      gapsInCurrent: gapList(cScope),
      // And the boundaries each run DECLARED — named, never paired: what a producer says it does not
      // examine is a fact about its scope, not a finding that can be fixed or appear.
      scopeStatementsInBaseline: statementList(bScope),
      scopeStatementsInCurrent: statementList(cScope),
    },
  };
}
