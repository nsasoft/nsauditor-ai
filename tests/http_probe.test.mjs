// tests/http_probe.test.mjs
// Run with: node --test
import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

import httpProbe from "../plugins/http_probe.mjs";

function startHttpServer(responder) {
  return new Promise((resolve, reject) => {
    const server = http.createServer(responder);
    server.on("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      resolve({ server, port: addr.port });
    });
  });
}

test("http_probe: classifies Epson-style headers as printer and captures banner", async () => {
  const { server, port } = await startHttpServer((req, res) => {
    res.statusCode = 200;
    res.statusMessage = "OK";
    res.setHeader("Server", "EPSON_Linux UPnP/1.0 Epson UPnP SDK/1.0");
    res.setHeader("X-Frame-Options", "SAMEORIGIN");
    res.setHeader("Content-Type", "text/html");
    res.end("<html>ok</html>");
  });

  try {
    const result = await httpProbe.run("127.0.0.1", port);
    assert.equal(result.up, true);
    assert.equal(result.type, "printer");
    // Plugin may not normalize to "EPSON HTTP Server"; accept the literal header value
    assert.ok(/epson/i.test(String(result.program || "")));
    assert.ok(Array.isArray(result.data) && result.data.length > 0);
    const banner = String(result.data[0].response_banner || "");
    assert.ok(banner.startsWith("200 OK"));
    assert.ok(banner.toLowerCase().includes("server: epson_linux upnp/1.0 epson upnp sdk/1.0"));
  } finally {
    server.close();
  }
});

test("http_probe: detects NETGEAR via WWW-Authenticate realm", async () => {
  const { server, port } = await startHttpServer((req, res) => {
    res.statusCode = 401;
    res.statusMessage = "Unauthorized";
    res.setHeader("WWW-Authenticate", "Basic realm=\"NETGEAR R8000\"");
    res.setHeader("Connection", "close");
    res.end();
  });

  try {
    const result = await httpProbe.run("127.0.0.1", port);
    assert.equal(result.up, true);
    assert.equal(result.type, "router");
    assert.ok(/^netgear/i.test(String(result.program || "")));
    const banner = String(result.data[0].response_banner || "");
    assert.ok(banner.startsWith("401 Unauthorized"));
    assert.ok(banner.toLowerCase().includes("www-authenticate: basic realm=\"netgear r8000\""));
  } finally {
    server.close();
  }
});

test("http_probe: detects dangerous HTTP methods via OPTIONS", async () => {
  const { server, port } = await startHttpServer((req, res) => {
    if (req.method === 'OPTIONS') {
      res.setHeader('Allow', 'GET, HEAD, POST, PUT, DELETE, OPTIONS');
      res.statusCode = 200;
      res.end();
    } else {
      res.statusCode = 200;
      res.setHeader('Server', 'test');
      res.end('ok');
    }
  });
  try {
    const result = await httpProbe.run("127.0.0.1", port);
    assert.ok(result.dangerousMethods.includes('PUT'));
    assert.ok(result.dangerousMethods.includes('DELETE'));
    assert.ok(result.allowedMethods.length >= 4);
    assert.ok(result.data.some(d => /dangerous.*method/i.test(d.probe_info)));
  } finally {
    server.close();
  }
});

test("http_probe: handles OPTIONS 405 gracefully — and a 405 with no Allow header is NOT TESTED, never \"none dangerous\"", async () => {
  const { server, port } = await startHttpServer((req, res) => {
    if (req.method === 'OPTIONS') {
      res.statusCode = 405;
      res.end();
    } else {
      res.statusCode = 200;
      res.setHeader('Server', 'test');
      res.end('ok');
    }
  });
  try {
    const result = await httpProbe.run("127.0.0.1", port);
    // 1.2.1: this asserted `[]` — an indeterminate reading as a pass. No Allow header was read, so nothing was observed.
    assert.equal(result.dangerousMethods, null);
    assert.equal(result.methodsTested, false);
    assert.equal(result.up, true);
  } finally {
    server.close();
  }
});

test("http_probe: connection refused path", async () => {
  const temp = await startHttpServer((_, res) => res.end("bye"));
  const freePort = temp.port;
  temp.server.close();

  const result = await httpProbe.run("127.0.0.1", freePort);
  assert.equal(result.up, false);
  assert.ok(result.data.some(d => /http\(s\) error:/i.test(d.probe_info)));
  assert.equal(result.program, null);
});

// 1.2.1 lane 3 (a4) / (s3), the audit seat's ruling: the methods are TESTED only when an Allow header was READ — the probe
// has no other way to see the list. An OPTIONS answer without Allow (a 405, a 200) and no answer at all are both NOT
// TESTED: methodsTested false, null arrays, never `[]`. All three used to read `dangerousMethods: []`, so "not tested"
// read as "none dangerous" to every consumer (scan_host, the Markdown, SARIF, --fail-on) — the indeterminate-as-PASS shape.
test("(fourth quadrant, first) an Allow header read is a test: methodsTested true, the list as advertised", async () => {
  const { server, port } = await startHttpServer((req, res) => {
    if (req.method === 'OPTIONS') { res.setHeader('Allow', 'GET, HEAD'); res.end(); return; }
    res.setHeader('Server', 'test'); res.end('ok');
  });
  try {
    const result = await httpProbe.run("127.0.0.1", port);
    assert.equal(result.methodsTested, true);
    assert.deepEqual(result.allowedMethods, ['GET', 'HEAD']);
    assert.deepEqual(result.dangerousMethods, []);
  } finally { server.close(); }
});

test("(fourth quadrant) an Allow header listing dangerous methods is a test that FOUND them", async () => {
  const { server, port } = await startHttpServer((req, res) => {
    if (req.method === 'OPTIONS') { res.setHeader('Allow', 'GET, PUT, DELETE'); res.end(); return; }
    res.setHeader('Server', 'test'); res.end('ok');
  });
  try {
    const result = await httpProbe.run("127.0.0.1", port);
    assert.equal(result.methodsTested, true);
    assert.deepEqual(result.dangerousMethods, ['PUT', 'DELETE']);
  } finally { server.close(); }
});

test("an OPTIONS 200 WITHOUT an Allow header is NOT TESTED — the server did not advertise, nothing was observed", async () => {
  const { server, port } = await startHttpServer((req, res) => {
    if (req.method === 'OPTIONS') { res.statusCode = 200; res.end(); return; }
    res.setHeader('Server', 'test'); res.end('ok');
  });
  try {
    const result = await httpProbe.run("127.0.0.1", port);
    assert.equal(result.methodsTested, false);
    assert.equal(result.dangerousMethods, null);
    assert.equal(result.allowedMethods, null);
    assert.ok(result.data.some((d) => /no Allow header.*not tested/i.test(d.probe_info)), JSON.stringify(result.data));
  } finally { server.close(); }
});

test("an OPTIONS that is NOT answered is NOT TESTED — methodsTested false, null arrays, and a row that says so", async () => {
  const { server, port } = await startHttpServer((req, res) => {
    if (req.method === 'OPTIONS') { req.socket.destroy(); return; }
    res.setHeader('Server', 'test'); res.end('ok');
  });
  try {
    const result = await httpProbe.run("127.0.0.1", port);
    assert.equal(result.up, true, 'positive control: the GET was answered');
    assert.equal(result.methodsTested, false);
    assert.equal(result.dangerousMethods, null, 'not tested is not "none dangerous"');
    assert.equal(result.allowedMethods, null);
    assert.ok(result.data.some((d) => /OPTIONS .*not answered.*not tested/i.test(d.probe_info)), JSON.stringify(result.data));
  } finally { server.close(); }
});
