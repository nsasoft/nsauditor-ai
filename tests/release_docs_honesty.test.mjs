// THE SHIPPED DOCS SAY WHAT 0.2.56 DOES — the release-doc fold before the publish (2026-09-30; the operator's rulings
// "Fix docs now + claim the name", "Fix all three now", "Keep it, explain it").
//
// (1) npx MAY ONLY RUN A PACKAGE THIS PROJECT PUBLISHES TO BE RUN. `nsauditor-ai-mcp` is a BIN inside `nsauditor-ai`,
//     not a package. When npx does not find that bin installed it asks the npm REGISTRY for a package of that name, and
//     the name was unclaimed: a doc printing `npx nsauditor-ai-mcp` (or a Desktop block whose command is npx) sent every
//     reader without the bin to whatever anyone published under it. Only COMMAND POSITIONS are read — fenced code and
//     inline code spans — because prose that names npx runs nothing; the one exemption is POSITIONAL, the warning form
//     "never `npx …`" immediately before the span.
// (2) Below the Community floor the symptom is the MEASURED one: Community 0.2.55 still loads the Enterprise plugins,
//     but the scan skips Enterprise's intelligence, analysis-agent and compliance stages. "The scan runs as Community"
//     was driven false on a 0.2.55 sandbox (the plugins load; only the index import throws).
// (3) NSA_ALLOW_ALL_HOSTS: over MCP it turns off the check of what a host name RESOLVES to, so a name resolving to a
//     loopback or cloud-metadata address gets through (driven in both arms); the webhook guard never reads it.
// (4) Two scans get distinct directories when their plugin runs FINISH in the same second — the stamp is taken after
//     `await pm.run`, not when the scan starts.
//
// SUBJECT — derived: the .md files `npm pack --dry-run` ships. FOURTH QUADRANT FIRST: the accepted forms stay green
// before the defect's own shape is asserted red.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

/** The .md files the tarball carries — derived, never listed by hand. */
function shippedMarkdown() {
  const r = spawnSync('npm', ['pack', '--dry-run', '--json'], { cwd: ROOT, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  const md = JSON.parse(r.stdout)[0].files.map((f) => f.path).filter((p) => p.endsWith('.md'));
  assert.ok(md.includes('README.md'), `the subject derivation is blind: README.md is not among ${md.join(', ')}`);
  return md;
}

// ── (1) npx ──────────────────────────────────────────────────────────────────────────────────────────────────────────
const RUNNABLE = new Set(['nsauditor-ai', 'nsauditor-ai-agent-skill']);
const NPX = /\bnpx\b((?:\s+(?:-y|--yes|-q|--quiet|--no-install|--offline|(?:-p|--package)(?:=|\s+)[^\s`'"]+))*)\s+([@a-z0-9][^\s`'"]*)/g;
const pkgName = (s) => (s.startsWith('@') ? s.replace(/^(@[^/]+\/[^@]+)@.*$/, '$1') : s.replace(/@.*$/, ''));

/** Fenced lines and inline code spans of a markdown text, each with its offset in the source. */
function codeRegions(md) {
  const out = [];
  let off = 0;
  let fence = null;
  for (const line of md.split('\n')) {
    const f = /^\s*(`{3,}|~{3,})/.exec(line);
    if (fence) {
      if (f && f[1][0] === fence[0] && f[1].length >= fence.length) fence = null;
      // a shell / JS comment line is prose: only its inline code spans are commands — unless the comment IS a command,
      // commented out (`# npx …`, `# $ npx …`), which is read whole (v77-9, 1.3.0). Prose that merely names npx mid-line
      // ("when npx does not find that bin") is not a command and is not read.
      else if (/^\s*(?:#|\/\/)/.test(line)) {
        const cmd = /^(\s*(?:#|\/\/)\s*(?:\$\s*)?)(npx\b.*)$/.exec(line);
        if (cmd) out.push({ start: off + cmd[1].length, text: cmd[2] });
        else for (const s of line.matchAll(/`([^`]+)`/g)) out.push({ start: off + s.index + 1, text: s[1] });
      } else out.push({ start: off, text: line });
    } else if (f) {
      fence = f[1];
    } else {
      for (const s of line.matchAll(/`([^`]+)`/g)) out.push({ start: off + s.index + 1, text: s[1] });
    }
    off += line.length + 1;
  }
  return out;
}

/** { bad, ok }: every npx command position, judged; every Desktop block whose command is npx is bad. */
function npxCommands(md) {
  const bad = [];
  const ok = [];
  for (const r of codeRegions(md)) {
    if (/"command"\s*:\s*"npx"/.test(r.text)) bad.push(`a Desktop block runs npx: ${r.text.trim()}`);
    for (const m of r.text.matchAll(NPX)) {
      const p = /(?:-p|--package)(?:=|\s+)([^\s`'"]+)/.exec(m[1]);
      const name = pkgName(p ? p[1] : m[2]);
      if (RUNNABLE.has(name)) { ok.push(m[0]); continue; }
      if (/\bnever\s+`$/i.test(md.slice(0, r.start + m.index))) { ok.push(`never ${m[0]}`); continue; }
      bad.push(`npx runs \`${name}\`, which this project does not publish to be run: ${m[0]}`);
    }
  }
  return { bad, ok };
}

test('(q) npx: the forms that run OUR packages, a warning, and prose naming npx all stay green', () => {
  const { bad, ok } = npxCommands([
    '```bash', 'npx nsauditor-ai scan --host 192.0.2.1 --plugins all', '```',
    'Build it with `npx nsauditor-ai-agent-skill build-zip --out ~/Desktop`.',
    'Run the installed bin, never `npx nsauditor-ai-mcp`: when npx does not find that bin it asks the registry.',
    '```bash', '# Never `npx nsauditor-ai-mcp`: the server is a bin inside the nsauditor-ai package, and when npx does not', '# find that bin it looks the name up (no global install), which never starts this server', '```',
    // v77-9 (1.3.0): a COMMENTED-OUT command is read as a command — and one that runs OUR package stays green.
    '```bash', '# npx nsauditor-ai scan --host 192.0.2.1', '```',
  ].join('\n'));
  assert.deepEqual(bad, []);
  assert.equal(ok.length, 5, ok.join(' | '));
});

test('npx: an unowned name in any command position is red — bare, -y, after `--`, inline, and a Desktop npx block', () => {
  for (const md of [
    '```bash\nnpx nsauditor-ai-mcp\n```',
    '```bash\nnpx -y nsauditor-ai-mcp\n```',
    // v77-9 (1.3.0): a commented-out command — the guard read only backtick spans inside a comment, so these were invisible.
    '```bash\n# npx nsauditor-ai-mcp\n```',
    '```bash\n# $ npx -y nsauditor-ai-mcp\n```',
    '```bash\nclaude mcp add nsauditor-ai \\\n  -- npx nsauditor-ai-mcp\n```',
    'Or run `npx nsauditor-ai-mcp` with no global install.',
    'Use `npx --yes someone-elses-package`.',
    '```bash\nnpx -p someone-elses-package nsauditor-ai\n```',
    '```json\n{ "mcpServers": { "nsauditor-ai": { "command": "npx", "args": ["nsauditor-ai"] } } }\n```',
    // the exemption is positional: "never" elsewhere in the sentence does not reach the span
    'Never mind the install step and run `npx nsauditor-ai-mcp`.',
  ]) assert.equal(npxCommands(md).bad.length, 1, md);
});

test('npx: no shipped .md runs a package this project does not publish to be run (subject from npm pack)', () => {
  let accepted = 0;
  for (const rel of shippedMarkdown()) {
    const { bad, ok } = npxCommands(read(rel));
    assert.deepEqual(bad, [], `${rel}:\n  ${bad.join('\n  ')}`);
    accepted += ok.length;
  }
  // positive control: the corpus does print npx commands of our own, so a reader blind to them fails here
  assert.ok(accepted >= 2, `the npx reader accepted ${accepted} commands in the shipped docs — it is not reading them`);
});

// ── (2) below the floor ──────────────────────────────────────────────────────────────────────────────────────────────
const BELOW_FLOOR_FALSE = [/\b(?:runs?|running|ran) (?:silently )?as Community\b/i, /\bnot load at all\b/i,
  /(?<!index )\bwould not load below it\b/i, /\bload(?:s|ed)? it as "not installed"/i];
const BELOW_FLOOR_SYMPTOM = /plugins running while the scan skipped its intelligence,\s+analysis-agent and compliance stages/;

test('below the floor: no shipped .md says the scan runs as Community, and the README states the measured symptom', () => {
  for (const rel of shippedMarkdown()) {
    const s = read(rel);
    for (const re of BELOW_FLOOR_FALSE) assert.doesNotMatch(s, re, `${rel} carries a below-floor symptom 0.2.55 does not show`);
  }
  assert.match(read('README.md'), BELOW_FLOOR_SYMPTOM);
});

// ── (3) NSA_ALLOW_ALL_HOSTS ──────────────────────────────────────────────────────────────────────────────────────────
test('NSA_ALLOW_ALL_HOSTS: the README says what it opens over MCP, and never offers it for a rejected webhook', () => {
  const s = read('README.md');
  // 1.3.0 lane 1 B: allow-all no longer lifts the resolved-address check over MCP — it admits private
  // ranges only. The pre-1.3.0 disclosure ("a name that resolves to a loopback or cloud-metadata
  // address then gets through") became false with that change and must not survive in the README.
  assert.match(s, /It admits private ranges only: loopback, link-local and cloud-metadata addresses stay refused over\s+MCP/);
  assert.doesNotMatch(s, /name that resolves to a loopback or cloud-metadata address then gets\s+through/);
  assert.match(s, /does not pin the answer/);
  assert.match(s, /never the webhook guard/);
  assert.doesNotMatch(s, /Webhook URL rejected[^\n]*Use `NSA_ALLOW_ALL_HOSTS=1`/);
});

// ── (4) the same-second instant ──────────────────────────────────────────────────────────────────────────────────────
test('two scans of one host get distinct directories by when their plugin runs FINISHED, not when they started', () => {
  const s = read('README.md');
  assert.doesNotMatch(s, /started in\s+the same second/);
  assert.match(s, /whose plugin runs finished in the same second/);
});
