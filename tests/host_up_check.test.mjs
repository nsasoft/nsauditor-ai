// tests/host_up_check.test.mjs
// Run with: node --test
import { test } from "node:test";
import assert from "node:assert/strict";

import hostUpCheck from "../plugins/host_up_check.mjs";

test("host_up_check: localhost is reachable; includes ICMP/TCP/UDP probes", { timeout: 20_000 }, async () => {
  const res = await hostUpCheck.run("127.0.0.1");

  // Basic shape
  assert.equal(typeof res.up, "boolean");
  assert.ok(Array.isArray(res.data));

  // ICMP probe should be recorded
  const icmp = res.data.find(d => d.probe_protocol === "icmp");
  assert.ok(icmp, "expected an ICMP probe entry");

  // TCP common ports the plugin probes
  const expectedTcp = [21, 22, 80, 443, 3389];
  for (const p of expectedTcp) {
    assert.ok(
      res.data.some(d => d.probe_protocol === "tcp" && d.probe_port === p),
      `missing TCP probe for port ${p}`
    );
  }

  // UDP high port heuristic
  assert.ok(
    res.data.some(d => d.probe_protocol === "udp" && d.probe_port === 54321),
    "missing UDP probe 54321"
  );

  // Generally should be true for localhost
  assert.equal(res.up, true);
});

test("host_up_check: result object fields are stable", { timeout: 20_000 }, async () => {
  const res = await hostUpCheck.run("127.0.0.1");

  if (res.router_info) {
    assert.equal(typeof res.router_info, "object");
    assert.ok("name" in res.router_info);
    assert.ok("version" in res.router_info);
  }

  for (const d of res.data) {
    assert.ok(["icmp", "tcp", "udp"].includes(d.probe_protocol));
    if (d.probe_protocol === "icmp") {
      assert.equal(d.probe_port, null);
    } else {
      assert.equal(typeof d.probe_port, "number");
    }
    assert.equal(typeof d.probe_info, "string");
  }
});
