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

test("http_probe: handles OPTIONS 405 gracefully", async () => {
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
    assert.deepEqual(result.dangerousMethods, []);
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
