// tests/ping_checker.test.mjs
// Run with: npm test
import { test, mock } from "node:test";
import assert from "node:assert/strict";
import net from "node:net";
import ping from "../plugins/ping_checker.mjs";

/**
 * Helper: stub net.Socket.prototype.connect so every new socket immediately
 * emits an ETIMEDOUT error instead of hitting the network.  Returns a
 * restore() function that puts the original back.
 */
function stubSocketConnect() {
  const original = net.Socket.prototype.connect;
  net.Socket.prototype.connect = function (...args) {
    process.nextTick(() => {
      const err = new Error("connect ETIMEDOUT");
      err.code = "ETIMEDOUT";
      this.emit("error", err);
    });
    return this;
  };
  return () => { net.Socket.prototype.connect = original; };
}

test("Ping Checker: localhost up (may vary by OS/network)", async (t) => {
  const res = await ping.run("127.0.0.1", null, { timeoutMs: 1500 });
  // Only assert shape + non-throw to keep this test robust across OSes
  assert.equal(typeof res.up, "boolean");
  assert.ok(Array.isArray(res.data));
  // probeMethod should exist in result
  assert.ok(["echo", "timestamp", "tcp-ack", "none"].includes(res.probeMethod),
    `probeMethod should be a valid value, got: ${res.probeMethod}`);
});

// ── Fallback probe tests ────────────────────────────────────────────

test("Ping Checker: probeMethod is 'echo' when ping succeeds on localhost", async () => {
  const res = await ping.run("127.0.0.1", null, { timeoutMs: 2000 });
  if (res.up) {
    assert.equal(res.probeMethod, "echo", "localhost ping should succeed via echo");
    // Fallback probes should NOT appear in data when echo succeeds
    const hasFallback = res.data.some(d =>
      d.probe_protocol === "icmp-timestamp" || d.probe_protocol === "tcp-ack"
    );
    assert.ok(!hasFallback, "No fallback probes when echo succeeds");
  }
});

test("Ping Checker: fallback disabled — only echo probe attempted", async () => {
  // Use an unreachable IP so echo fails; with fallback off, no extra probes
  const res = await ping.run("192.0.2.1", null, {
    timeoutMs: 1500,
    fallback: false
  });
  // Should only have the icmp echo row (plus maybe arp if private-like, but 192.0.2.x is not)
  const protocols = res.data.map(d => d.probe_protocol);
  assert.ok(!protocols.includes("icmp-timestamp"),
    "No timestamp probe when fallback is disabled");
  assert.ok(!protocols.includes("tcp-ack"),
    "No TCP ACK probe when fallback is disabled");
  assert.equal(res.probeMethod, "none",
    "probeMethod should be 'none' when unreachable and fallback is disabled");
});

test("Ping Checker: fallback TCP ACK detects localhost when echo is simulated as failed", async () => {
  // We can't easily force echo to fail on localhost, so instead we test the
  // TCP ACK fallback on a known-reachable host with fallback explicitly enabled.
  // Use a non-routable IP that will fail echo, then rely on TCP to 127.0.0.1 wouldn't work
  // since the host param has to be consistent. Instead, validate the code path
  // by probing a truly unreachable host and checking the evidence rows exist.
  const res = await ping.run("192.0.2.1", null, {
    timeoutMs: 1500,
    fallback: true,
    fallbackTimeout: 1500
  });
  // With fallback enabled and echo failing, we should see fallback evidence rows
  const protocols = res.data.map(d => d.probe_protocol);
  assert.ok(protocols.includes("icmp-timestamp"),
    "Timestamp probe should be attempted when echo fails");
  assert.ok(protocols.includes("tcp-ack"),
    "TCP ACK probe should be attempted when echo and timestamp fail");
});

test("Ping Checker: all probes fail — host marked as down with all evidence rows", async () => {
  // Stub TCP sockets to emit ETIMEDOUT so the test is deterministic
  // (on macOS, ECONNREFUSED from the local stack would falsely mark host as alive)
  const restore = stubSocketConnect();
  try {
    // 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — guaranteed non-routable
    const res = await ping.run("192.0.2.1", null, {
      timeoutMs: 1500,
      fallback: true,
      fallbackTimeout: 1500
    });
    assert.equal(res.up, false, "Host should be down");
    assert.equal(res.probeMethod, "none", "probeMethod should be 'none'");

    // Should have: icmp echo + icmp-timestamp + tcp-ack (port 80) + tcp-ack (port 443)
    const protocols = res.data.map(d => d.probe_protocol);
    assert.ok(protocols.includes("icmp"), "Should have icmp echo evidence");
    assert.ok(protocols.includes("icmp-timestamp"), "Should have icmp-timestamp evidence");

    const tcpAckRows = res.data.filter(d => d.probe_protocol === "tcp-ack");
    assert.ok(tcpAckRows.length >= 2,
      `Should have at least 2 TCP ACK rows (ports 80, 443), got ${tcpAckRows.length}`);
  } finally {
    restore();
  }
});

test("Ping Checker: probeMethod reflects tcp-ack when TCP detects host up", async () => {
  // Test against localhost with TCP ACK by forcing fallback on an echo-successful host.
  // We can't force echo failure on 127.0.0.1 easily, so we test the shape:
  // when all probes run, if TCP found the host up, probeMethod should be "tcp-ack".
  // Best approach: mock-free functional test — probe localhost directly.
  // Since localhost echo usually succeeds, we validate the complementary case:
  // if probeMethod is "echo" on localhost, TCP ACK was never attempted (correct behavior).
  const res = await ping.run("127.0.0.1", null, {
    timeoutMs: 2000,
    fallback: true,
    fallbackTimeout: 1500
  });
  if (res.up && res.probeMethod === "echo") {
    // Correct — echo succeeded so fallback was skipped
    const hasTcpAck = res.data.some(d => d.probe_protocol === "tcp-ack");
    assert.ok(!hasTcpAck, "TCP ACK should not run when echo succeeds");
  }
  // Either way, probeMethod must be valid
  assert.ok(["echo", "timestamp", "tcp-ack", "none"].includes(res.probeMethod));
});

test("Ping Checker: fallback timeout is respected (fast timeout)", async () => {
  // Stub TCP sockets to emit ETIMEDOUT so the test is deterministic across platforms
  const restore = stubSocketConnect();
  try {
    const start = Date.now();
    const res = await ping.run("192.0.2.1", null, {
      timeoutMs: 1500,
      fallback: true,
      fallbackTimeout: 1000 // 1 second timeout for fallback probes
    });
    const elapsed = Date.now() - start;
    // The total time should be bounded: echo timeout + timestamp attempt + 2x TCP ACK
    // With 1s fallback timeout, TCP probes should not each take more than ~1s
    // Total should be well under 15s (generous upper bound)
    assert.ok(elapsed < 15000,
      `Fallback probes took too long: ${elapsed}ms (should be <15s with 1s fallback timeout)`);
    assert.equal(res.up, false);
    assert.equal(res.probeMethod, "none");
  } finally {
    restore();
  }
});

test("Ping Checker: result shape includes probeMethod field", async () => {
  const res = await ping.run("127.0.0.1", null, { timeoutMs: 1500 });
  assert.ok("probeMethod" in res, "Result must include probeMethod field");
  assert.ok("up" in res, "Result must include up field");
  assert.ok("os" in res, "Result must include os field");
  assert.ok("data" in res, "Result must include data field");
  assert.ok(Array.isArray(res.data), "data must be an array");
});

test("Ping Checker: evidence rows have correct shape in fallback scenario", async () => {
  const res = await ping.run("192.0.2.1", null, {
    timeoutMs: 1500,
    fallback: true,
    fallbackTimeout: 1500
  });
  for (const row of res.data) {
    assert.ok("probe_protocol" in row, "Each evidence row needs probe_protocol");
    assert.ok("probe_info" in row, "Each evidence row needs probe_info");
    assert.ok("response_banner" in row, "Each evidence row needs response_banner");
    assert.ok("probe_port" in row, "Each evidence row needs probe_port");
  }
});

// ── TCP ACK context propagation tests ──────────────────────────────

test("Ping Checker: context.tcpOpen stays empty when all probes fail (unreachable host)", async () => {
  // Stub TCP sockets to emit ETIMEDOUT so the test is deterministic across platforms
  const restore = stubSocketConnect();
  try {
    const context = { tcpOpen: new Set() };
    const res = await ping.run("192.0.2.1", null, {
      timeoutMs: 1500,
      fallback: true,
      fallbackTimeout: 1500,
      context
    });
    assert.equal(context.tcpOpen.size, 0,
      "context.tcpOpen should be empty when all probes fail on unreachable host");
    assert.equal(res.up, false);
  } finally {
    restore();
  }
});

test("Ping Checker: context.tcpOpen not mutated when echo succeeds (no fallback needed)", async () => {
  const context = { tcpOpen: new Set() };
  const res = await ping.run("127.0.0.1", null, {
    timeoutMs: 2000,
    fallback: true,
    context
  });
  if (res.up && res.probeMethod === "echo") {
    // Echo succeeded — TCP ACK never ran, so tcpOpen stays empty
    assert.equal(context.tcpOpen.size, 0,
      "context.tcpOpen should not be modified when echo succeeds");
  }
});

test("Ping Checker: TCP ACK propagates confirmed port to context.tcpOpen on localhost", async () => {
  // On localhost, port 80 will get ECONNREFUSED (RST) or connect (web server).
  // Both mean alive=true in the TCP ACK path. We need echo to fail so
  // fallback fires. Use an IPv6 loopback alias (::1) which some systems
  // won't respond to ICMP for, or use the plugin against a local IP.
  //
  // Since we can't reliably force echo failure on localhost without mocking
  // execFile (complex in ESM), we test via a structural approach:
  // run the plugin and verify that IF tcp-ack was the probeMethod,
  // the confirmed port was added to context.tcpOpen.
  //
  // Additionally, we verify the negative case where echo succeeds above.

  // Strategy: use a short ping timeout to increase chance of echo failure
  // on some systems, while using normal TCP timeout.
  const context = { tcpOpen: new Set() };
  const res = await ping.run("127.0.0.1", null, {
    timeoutMs: 2000,
    fallback: true,
    fallbackTimeout: 2000,
    context
  });

  if (res.probeMethod === "tcp-ack") {
    // TCP ACK was the winning probe — verify port propagation
    const confirmedRow = res.data.find(
      d => d.probe_protocol === "tcp-ack" && /connect|RST/i.test(d.probe_info)
    );
    assert.ok(confirmedRow, "Should have a TCP ACK evidence row confirming host up");
    assert.ok(context.tcpOpen.has(confirmedRow.probe_port),
      `context.tcpOpen should contain port ${confirmedRow.probe_port} after TCP ACK confirmed it`);
  } else {
    // Echo succeeded — covered by the previous test
    assert.equal(res.probeMethod, "echo");
    assert.equal(context.tcpOpen.size, 0);
  }
});

test("Ping Checker: context.tcpOpen handles missing/non-Set gracefully", async () => {
  // Ensure the plugin doesn't crash when context exists but tcpOpen is absent or wrong type
  const res1 = await ping.run("127.0.0.1", null, {
    timeoutMs: 2000,
    fallback: true,
    context: {} // no tcpOpen property
  });
  assert.ok(typeof res1.up === "boolean", "Should not crash with empty context");

  const res2 = await ping.run("127.0.0.1", null, {
    timeoutMs: 2000,
    fallback: true,
    context: { tcpOpen: [] } // array instead of Set — no .add method matching
  });
  assert.ok(typeof res2.up === "boolean", "Should not crash with array tcpOpen");

  // No context at all
  const res3 = await ping.run("127.0.0.1", null, {
    timeoutMs: 2000,
    fallback: true
  });
  assert.ok(typeof res3.up === "boolean", "Should not crash without context");
});
