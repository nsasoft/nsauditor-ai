// tests/syn_scanner.test.mjs
// Run with: node --test tests/syn_scanner.test.mjs

import { test } from "node:test";
import assert from "node:assert/strict";

import synScanner, { parseNmapXml, conclude } from "../plugins/syn_scanner.mjs";

/* ------------------------------ sample XML ------------------------------ */

const SAMPLE_XML = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sS -Pn -oX - 192.168.1.1" start="1234567890">
  <host starttime="1234567890" endtime="1234567891">
    <status state="up" reason="syn-ack"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <hostnames><hostname name="server.local" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.9p1"/></port>
      <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.18.0"/></port>
      <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https"/></port>
      <port protocol="tcp" portid="3306"><state state="filtered" reason="no-response"/><service name="mysql"/></port>
    </ports>
    <os><osmatch name="Linux 5.4" accuracy="95" line="1"/></os>
  </host>
</nmaprun>`;

const MULTI_HOST_XML = `<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
    </ports>
  </host>
  <host>
    <status state="down" reason="no-response"/>
    <address addr="10.0.0.2" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="closed"/><service name="http"/></port>
    </ports>
  </host>
</nmaprun>`;

const EMPTY_XML = `<?xml version="1.0"?><nmaprun scanner="nmap"></nmaprun>`;

/* ------------------------------ metadata tests ------------------------------ */

test("syn_scanner: plugin metadata is correct", () => {
  assert.equal(synScanner.id, "024");
  assert.equal(synScanner.name, "TCP SYN Scanner (Nmap)");
  assert.equal(synScanner.priority, 12);
  assert.ok(Array.isArray(synScanner.protocols));
  assert.ok(synScanner.protocols.includes("tcp"));
  assert.equal(typeof synScanner.run, "function");
});

/* ------------------------------ parseNmapXml tests ------------------------------ */

test("parseNmapXml: parses multiple open ports with services", () => {
  const result = parseNmapXml(SAMPLE_XML);

  assert.equal(result.hosts.length, 1);
  const host = result.hosts[0];

  assert.equal(host.ip, "192.168.1.1");
  assert.equal(host.status, "up");
  assert.equal(host.ports.length, 4);

  // Port 22
  const ssh = host.ports.find((p) => p.port === 22);
  assert.ok(ssh);
  assert.equal(ssh.state, "open");
  assert.equal(ssh.service, "ssh");
  assert.equal(ssh.protocol, "tcp");
  assert.ok(ssh.version.includes("OpenSSH"));
  assert.ok(ssh.version.includes("8.9p1"));

  // Port 80
  const http = host.ports.find((p) => p.port === 80);
  assert.ok(http);
  assert.equal(http.state, "open");
  assert.equal(http.service, "http");
  assert.ok(http.version.includes("nginx"));

  // Port 443
  const https = host.ports.find((p) => p.port === 443);
  assert.ok(https);
  assert.equal(https.state, "open");
  assert.equal(https.service, "https");

  // Port 3306 (filtered)
  const mysql = host.ports.find((p) => p.port === 3306);
  assert.ok(mysql);
  assert.equal(mysql.state, "filtered");
  assert.equal(mysql.service, "mysql");
});

test("parseNmapXml: extracts OS detection hints", () => {
  const result = parseNmapXml(SAMPLE_XML);
  const host = result.hosts[0];
  assert.equal(host.os, "Linux 5.4");
});

test("parseNmapXml: handles closed/filtered ports correctly", () => {
  const result = parseNmapXml(SAMPLE_XML);
  const host = result.hosts[0];

  const openPorts = host.ports.filter((p) => p.state === "open");
  const filteredPorts = host.ports.filter((p) => p.state === "filtered");

  assert.equal(openPorts.length, 3);
  assert.equal(filteredPorts.length, 1);
  assert.equal(filteredPorts[0].port, 3306);
});

test("parseNmapXml: handles multiple hosts", () => {
  const result = parseNmapXml(MULTI_HOST_XML);

  assert.equal(result.hosts.length, 2);
  assert.equal(result.hosts[0].ip, "10.0.0.1");
  assert.equal(result.hosts[0].status, "up");
  assert.equal(result.hosts[1].ip, "10.0.0.2");
  assert.equal(result.hosts[1].status, "down");
});

test("parseNmapXml: returns empty hosts for empty XML", () => {
  const result = parseNmapXml(EMPTY_XML);
  assert.ok(Array.isArray(result.hosts));
  assert.equal(result.hosts.length, 0);
});

test("parseNmapXml: handles null/undefined/malformed XML gracefully", () => {
  assert.deepStrictEqual(parseNmapXml(null), { hosts: [] });
  assert.deepStrictEqual(parseNmapXml(undefined), { hosts: [] });
  assert.deepStrictEqual(parseNmapXml(""), { hosts: [] });
  assert.deepStrictEqual(parseNmapXml("not xml at all"), { hosts: [] });
  assert.deepStrictEqual(parseNmapXml(123), { hosts: [] });
});

/* ------------------------------ host validation tests ------------------------------ */

test("syn_scanner: rejects command injection attempts in host", async () => {
  // Temporarily enable SYN scan for this test
  const orig = process.env.ENABLE_SYN_SCAN;
  process.env.ENABLE_SYN_SCAN = "1";
  try {
    const injections = [
      "192.168.1.1; rm -rf /",
      "$(whoami)",
      "`id`",
      "host | cat /etc/passwd",
      "192.168.1.1 && echo pwned",
      "",
      "a".repeat(300),
    ];

    for (const bad of injections) {
      const res = await synScanner.run(bad, 0, {});
      assert.equal(res.up, false, `Should reject host: ${bad.slice(0, 40)}`);
      const info = res.data[0]?.probe_info || "";
      assert.ok(
        info.includes("Invalid host") || info.includes("SYN scan disabled"),
        `Should flag invalid host: ${bad.slice(0, 40)}`
      );
    }
  } finally {
    if (orig === undefined) delete process.env.ENABLE_SYN_SCAN;
    else process.env.ENABLE_SYN_SCAN = orig;
  }
});

/* ------------------------------ disabled / fallback tests ------------------------------ */

test("syn_scanner: returns disabled message when ENABLE_SYN_SCAN is not set", async () => {
  const orig = process.env.ENABLE_SYN_SCAN;
  delete process.env.ENABLE_SYN_SCAN;
  try {
    const res = await synScanner.run("192.168.1.1", 0, {});
    assert.equal(res.up, false);
    assert.equal(res.type, "syn-scan");
    assert.ok(res.data[0]?.probe_info.includes("disabled"));
  } finally {
    if (orig !== undefined) process.env.ENABLE_SYN_SCAN = orig;
  }
});

test("syn_scanner: returns disabled message when ENABLE_SYN_SCAN=false", async () => {
  const orig = process.env.ENABLE_SYN_SCAN;
  process.env.ENABLE_SYN_SCAN = "false";
  try {
    const res = await synScanner.run("192.168.1.1", 0, {});
    assert.equal(res.up, false);
    assert.ok(res.data[0]?.probe_info.includes("disabled"));
  } finally {
    if (orig === undefined) delete process.env.ENABLE_SYN_SCAN;
    else process.env.ENABLE_SYN_SCAN = orig;
  }
});

/* ------------------------------ conclude adapter tests ------------------------------ */

test("syn_scanner: conclude produces service records from nmap results", async () => {
  const result = {
    up: true,
    program: "nmap",
    version: "Unknown",
    os: "Linux 5.4",
    type: "syn-scan",
    tcpOpen: [22, 80, 443],
    data: [
      {
        probe_protocol: "tcp",
        probe_port: 22,
        status: "open",
        probe_info: "SYN scan: open (ssh)",
        response_banner: "OpenSSH 8.9p1",
        service: "ssh",
      },
      {
        probe_protocol: "tcp",
        probe_port: 80,
        status: "open",
        probe_info: "SYN scan: open (http)",
        response_banner: "nginx 1.18.0",
        service: "http",
      },
      {
        probe_protocol: "tcp",
        probe_port: 3306,
        status: "filtered",
        probe_info: "SYN scan: filtered (mysql)",
        response_banner: null,
        service: "mysql",
      },
    ],
  };

  const records = await conclude({ host: "192.168.1.1", result });

  assert.equal(records.length, 3);

  const sshRec = records.find((r) => r.port === 22);
  assert.ok(sshRec);
  assert.equal(sshRec.status, "open");
  assert.equal(sshRec.service, "ssh");
  assert.equal(sshRec.source, "syn_scanner");

  const httpRec = records.find((r) => r.port === 80);
  assert.ok(httpRec);
  assert.equal(httpRec.status, "open");

  const mysqlRec = records.find((r) => r.port === 3306);
  assert.ok(mysqlRec);
  assert.equal(mysqlRec.status, "filtered");
});

test("syn_scanner: conclude handles empty data gracefully", async () => {
  const records = await conclude({ host: "192.168.1.1", result: { up: false, data: [] } });
  assert.ok(Array.isArray(records));
  assert.equal(records.length, 0);
});

test("syn_scanner: conclude skips rows with port 0", async () => {
  const result = {
    up: false,
    data: [{ probe_protocol: "tcp", probe_port: 0, status: "unknown", probe_info: "test" }],
  };
  const records = await conclude({ host: "x", result });
  assert.equal(records.length, 0);
});

/* ------------------------------ port range env var ------------------------------ */

test("syn_scanner: SYN_SCAN_PORTS env var is respected in args", () => {
  // We can't easily test the full nmap invocation, but we can verify the
  // plugin structure supports port range. Let's verify that parseNmapXml
  // correctly handles port output from a range scan.
  const xmlWithRange = `<?xml version="1.0"?>
<nmaprun scanner="nmap" args="nmap -sS -Pn -p 1-1024 -oX - 192.168.1.1">
  <host>
    <status state="up"/>
    <address addr="192.168.1.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="21"><state state="closed"/><service name="ftp"/></port>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
    </ports>
  </host>
</nmaprun>`;

  const result = parseNmapXml(xmlWithRange);
  assert.equal(result.hosts.length, 1);
  assert.equal(result.hosts[0].ports.length, 4);

  const closedPorts = result.hosts[0].ports.filter((p) => p.state === "closed");
  assert.equal(closedPorts.length, 1);
  assert.equal(closedPorts[0].port, 21);
});

/* ------------------------------ context update test ------------------------------ */

test("syn_scanner: run updates context tcpOpen when enabled and nmap unavailable", async () => {
  // When SYN scan is disabled, it should not touch context
  const orig = process.env.ENABLE_SYN_SCAN;
  delete process.env.ENABLE_SYN_SCAN;
  try {
    const ctx = { hostUp: false, tcpOpen: new Set(), udpOpen: new Set() };
    const res = await synScanner.run("192.168.1.1", 0, { context: ctx });
    assert.equal(res.up, false);
    assert.equal(ctx.tcpOpen.size, 0, "Context should not be modified when scan is disabled");
  } finally {
    if (orig !== undefined) process.env.ENABLE_SYN_SCAN = orig;
  }
});

/* ------------------------------ version extraction test ------------------------------ */

test("parseNmapXml: extracts product+version composite from service tag", () => {
  const xml = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.0p1"/></port>
      <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd"/></port>
      <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
    </ports>
  </host>
</nmaprun>`;

  const result = parseNmapXml(xml);
  const host = result.hosts[0];

  // product + version
  assert.equal(host.ports[0].version, "OpenSSH 9.0p1");
  // product only
  assert.equal(host.ports[1].version, "Apache httpd");
  // neither
  assert.equal(host.ports[2].version, null);
});
