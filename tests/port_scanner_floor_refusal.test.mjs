// tests/port_scanner_floor_refusal.test.mjs
//
// AN EMPTY DEFAULT PORT SET IS "COULD NOT MEASURE", NEVER "NOTHING LISTENING" — board item 18.
//
// The package's own config/services.json is the floor under the default sweep. When it could not
// be read (a 0600 install — every published tarball carried that mode until 0.2.55 — a missing
// file, a broken edit) or parsed to zero ports, run() fell through to its empty return:
// `up:false` with every bucket empty, in about a millisecond, having probed nothing. Downstream
// that is indistinguishable from a host with nothing listening, and every plugin gated on
// `tcp_open` is then skipped. The scanner now REFUSES — it throws, which the plugin manager
// records as status `error`, the channel every consumer already reads as "not measured".
//
// ⚠️ FOURTH QUADRANT FIRST: an intact floor still yields its ports, so the refusal cannot be
// satisfied by refusing everything.
import { test } from "node:test";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

import portScanner, { loadConfigPortsFromServicesJson } from "../plugins/port_scanner.mjs";

const PKG_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REFUSAL = /port scanner refused: the default port set is empty/;

function floorRoot(content) {
  const r = fs.mkdtempSync(path.join(os.tmpdir(), "ps-floor-"));
  fs.mkdirSync(path.join(r, "config"));
  if (content !== undefined) fs.writeFileSync(path.join(r, "config", "services.json"), content);
  return r;
}
const EMPTY_CWD = () => fs.mkdtempSync(path.join(os.tmpdir(), "ps-cwd-"));

test("FOURTH QUADRANT — the shipped floor yields ports, and the loader says it came from the package", async () => {
  const cwd = EMPTY_CWD();
  try {
    const set = await loadConfigPortsFromServicesJson(cwd, PKG_ROOT);
    assert.ok(set.tcp.length + set.udp.length > 0, "the shipped config/services.json must yield ports");
    assert.equal(set.source, "package");
  } finally { fs.rmSync(cwd, { recursive: true, force: true }); }
});

test("a floor that parses to ZERO ports is refused — run() throws, it does not return up:false", async () => {
  const root = floorRoot(JSON.stringify({ services: [] }));
  const cwd = EMPTY_CWD();
  try {
    await assert.rejects(portScanner.run("127.0.0.1", 0, { _servicesFloorRoot: root, _servicesCwd: cwd }), REFUSAL);
  } finally { for (const d of [root, cwd]) fs.rmSync(d, { recursive: true, force: true }); }
});

test("a MISSING floor is refused, and the refusal names the path it could not use", async () => {
  const root = floorRoot(undefined);
  const cwd = EMPTY_CWD();
  try {
    await assert.rejects(portScanner.run("127.0.0.1", 0, { _servicesFloorRoot: root, _servicesCwd: cwd }),
      (e) => REFUSAL.test(e.message) && e.message.includes(path.join(root, "config", "services.json")));
  } finally { for (const d of [root, cwd]) fs.rmSync(d, { recursive: true, force: true }); }
});

test("an UNREADABLE floor (mode 0000) is refused", { skip: process.getuid?.() === 0 ? "root reads a 0000 file" : false }, async () => {
  const root = floorRoot(JSON.stringify({ services: [{ port: 22, protocol: "tcp" }] }));
  const cwd = EMPTY_CWD();
  fs.chmodSync(path.join(root, "config", "services.json"), 0o000);
  try {
    await assert.rejects(portScanner.run("127.0.0.1", 0, { _servicesFloorRoot: root, _servicesCwd: cwd }), REFUSAL);
  } finally {
    fs.chmodSync(path.join(root, "config", "services.json"), 0o644);
    for (const d of [root, cwd]) fs.rmSync(d, { recursive: true, force: true });
  }
});

test("EXTRAS from --ports do not rescue an unreadable default set — the sweep asked for was not possible", async () => {
  const root = floorRoot(JSON.stringify({}));
  const cwd = EMPTY_CWD();
  try {
    await assert.rejects(portScanner.run("127.0.0.1", 0, { _servicesFloorRoot: root, _servicesCwd: cwd, ports: "9/tcp" }), REFUSAL);
  } finally { for (const d of [root, cwd]) fs.rmSync(d, { recursive: true, force: true }); }
});

test("a caller's own override that yields ports is used with a broken floor — the floor is only needed when there is no override", async () => {
  const root = floorRoot(JSON.stringify({ services: [] }));
  const cwd = EMPTY_CWD();
  fs.mkdirSync(path.join(cwd, "config"));
  fs.writeFileSync(path.join(cwd, "config", "services.json"), JSON.stringify({ services: [{ port: 9, protocol: "tcp" }] }));
  try {
    const set = await loadConfigPortsFromServicesJson(cwd, root);
    assert.deepEqual(set, { tcp: [9], udp: [], source: "override" });
    const r = await portScanner.run("127.0.0.1", 0, { _servicesFloorRoot: root, _servicesCwd: cwd, timeoutMs: 200 });
    assert.equal(r.type, "port-scan");
  } finally { for (const d of [root, cwd]) fs.rmSync(d, { recursive: true, force: true }); }
});

test("EXPLICIT tcpPorts never read the floor, so a broken floor does not refuse them", async () => {
  const root = floorRoot(undefined);
  try {
    const r = await portScanner.run("127.0.0.1", 0, { _servicesFloorRoot: root, tcpPorts: [9], timeoutMs: 200 });
    assert.equal(r.type, "port-scan");
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});

test("THROUGH THE MANAGER — a refused floor is recorded as status `error` with the refusal, never `ran`", async () => {
  const { default: PluginManager } = await import("../plugin_manager.mjs");
  const root = floorRoot(JSON.stringify({ services: [] }));
  const cwd = EMPTY_CWD();
  try {
    const mgr = new PluginManager("/nonexistent");
    mgr.plugins = [{ ...portScanner, requirements: {},
      run: (h, p, o) => portScanner.run(h, p, { ...o, _servicesFloorRoot: root, _servicesCwd: cwd }) }];
    const { manifest } = await mgr._runOrchestrated("127.0.0.1", mgr.plugins);
    const entry = manifest.find((m) => m.id === "003");
    assert.ok(entry, "the port scanner must appear in the manifest");
    assert.equal(entry.status, "error", "a scanner that could not build its port set did not measure anything");
    assert.match(String(entry.reason), REFUSAL);
  } finally { for (const d of [root, cwd]) fs.rmSync(d, { recursive: true, force: true }); }
});
