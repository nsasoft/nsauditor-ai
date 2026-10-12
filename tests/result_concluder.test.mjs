// tests/result_concluder.test.mjs
// Run with: npm test  (which runs `node --test`)

import { test } from "node:test";
import assert from "node:assert/strict";
import concluder from "../plugins/result_concluder.mjs";

// Helper to build a plugin envelope
const wrap = (id, name, result) => ({ id, name, result });

test("Result Concluder: sorts services by port and summarizes correctly", async () => {
  // Synthesize results similar to your 192.168.1.3 example
  const results = [
    wrap("004", "FTP Banner Check", {
      up: true,
      program: "Unknown",
      version: "Unknown",
      data: [{ probe_protocol: "tcp", probe_port: 21, probe_info: "Connection refused - host up, FTP port closed" }],
    }),
    wrap("005", "Host Up Check", {
      up: true,
      os: "Linux",
      data: [
        { probe_protocol: "icmp", probe_port: null, probe_info: "Ping successful (TTL: 64, OS: Linux)" },
        { probe_protocol: "tcp", probe_port: 21, probe_info: "Timeout" },
        { probe_protocol: "tcp", probe_port: 22, probe_info: "Timeout" },
        { probe_protocol: "tcp", probe_port: 80, probe_info: "Timeout" },
        { probe_protocol: "tcp", probe_port: 443, probe_info: "Timeout" },
      ],
    }),
    wrap("006", "HTTP Probe", {
      up: false,
      program: "Unknown",
      version: "Unknown",
      data: [{ probe_protocol: "http", probe_port: 80, probe_info: "HTTP(S) error: connect ECONNREFUSED 192.168.1.3:80" }],
    }),
    wrap("006", "HTTP Probe", {
      up: false,
      program: "Unknown",
      version: "Unknown",
      data: [{ probe_protocol: "https", probe_port: 443, probe_info: "HTTP(S) error: connect ECONNREFUSED 192.168.1.3:443" }],
    }),
    wrap("001", "Ping Checker", {
      up: true,
      data: [{ probe_protocol: "icmp", probe_port: null, probe_info: "Host 192.168.1.3 is up (ping response received)" }],
    }),
    wrap("007", "SNMP Scanner", {
      up: false,
      program: "Unknown",
      version: "Unknown",
      data: [{ probe_protocol: "udp", probe_port: 161, probe_info: 'No SNMP response for community "public"' }],
    }),
    wrap("002", "SSH Scanner", {
      up: false,
      program: "Unknown",
      version: "Unknown",
      data: [{ probe_protocol: "tcp", probe_port: 22, probe_info: "Error: Timeout" }],
      type: "ssh",
    }),
  ];

  // Force SSH timeout policy to "filtered" for this test
  process.env.CONCLUDER_SSH_TIMEOUT_AS = "filtered";

  const res = await concluder.run(results);
  assert.ok(res.summary && typeof res.summary === "string");

  // Services sorted by port ascending
  const ports = res.services.map((s) => s.port);
  assert.deepEqual(ports, [...ports].sort((a, b) => a - b));

  // OS guessed from Host Up Check
  assert.equal(res.host.os, "Linux");

  // Check a few statuses (tolerant for SNMP wording differences)
  const bySvc = Object.fromEntries(res.services.map((s) => [s.service + ":" + s.port, s]));
  // FLIPPED DELIBERATELY at EE 2.0.0 / Community 1.0.0 (4(b), tasks/release-2.0.0/f4-phantom-rows-design.md). This leg used
  // to assert `bySvc["ftp:21"].status === "closed"` and `bySvc["ssh:22"].status === "filtered"` — a SERVICE row for a port
  // whose own authoritative adapter identified nothing. That is the phantom shape: a refused FTP connect and an SSH timeout
  // listed as services in the report, the CSV, SARIF and the AI payload. The intent survives: the refusal is recorded as
  // EVIDENCE carrying its reason, and no ftp:21 or ssh:22 service exists.
  assert.equal(bySvc["ftp:21"], undefined, "a refused FTP port is not a service");
  assert.equal(bySvc["ssh:22"], undefined, "an SSH timeout is not a service");
  const ev = (port) => res.evidence.find((e) => e.protocol === "tcp" && e.port === port && e.reason);
  assert.equal(ev(21)?.status, "closed"); // refused => closed, as the adapter said
  assert.match(ev(21).reason, /not identified by its adapter/);
  assert.equal(ev(22)?.status, "filtered"); // SSH policy applied — to the evidence row now
  // UDP is untouched (a DECLARED LIMIT: a UDP non-answer is open|filtered, and the delta's UDP measurement reads the row).
  assert.ok(["no response", "filtered"].includes(bySvc["snmp:161"].status));
});

test("Result Concluder: SSH timeout policy obeys env", async () => {
  const results = [
    wrap("002", "SSH Scanner", {
      up: false,
      program: "Unknown",
      version: "Unknown",
      data: [{ probe_protocol: "tcp", probe_port: 22, probe_info: "Error: Timeout" }],
      type: "ssh",
    }),
  ];

  // FLIPPED DELIBERATELY at EE 2.0.0 / Community 1.0.0 (4(b)). This leg used to read `services[0].status` — so a timed-out
  // SSH probe, the one record in the run, was concluded as a SERVICE whose status the policy set. What it was guarding is
  // that a timeout is never read as 'open'; the phantom shape was the service row itself. Under every policy the timeout is
  // now no service and no false 'open': it is evidence carrying the reason, and the policy still names its status.
  for (const policy of ["closed", "unknown", "filtered"]) {
    process.env.CONCLUDER_SSH_TIMEOUT_AS = policy;
    const res = await concluder.run(results);
    assert.deepEqual(res.services, [], `policy ${policy}: a timed-out SSH probe is not a service`);
    const row = res.evidence.find((e) => e.protocol === "tcp" && e.port === 22 && e.reason);
    assert.ok(row, `policy ${policy}: the timeout is recorded as evidence with its reason`);
    assert.equal(row.status, policy);
    assert.notEqual(row.status, "open");
  }
});

test("Result Concluder: meta entries excluded from services, real services kept", async () => {
  const results = [
    // Real services
    wrap("002", "SSH Scanner", {
      up: true, program: "OpenSSH", version: "8.9",
      data: [{ probe_protocol: "tcp", probe_port: 22, probe_info: "SSH-2.0-OpenSSH_8.9" }],
      type: "ssh",
    }),
    wrap("009", "DNS Scanner", {
      up: true, program: "dnsmasq", version: "2.86",
      data: [{ probe_protocol: "udp", probe_port: 53, probe_info: "DNS response received" }],
    }),
    wrap("006", "HTTP Probe", {
      up: true, program: "nginx", version: "1.22",
      data: [{ probe_protocol: "tcp", probe_port: 443, probe_info: "HTTPS open" }],
    }),
    // Meta: assessment (protocol=assessment, port=0). Enterprise's zero-trust assessment is plugin 1023; this fixture
    // said "050" — the TRIBE API probe — which the 1.3.0 concluder, resolving adapters by id, now actually reaches.
    wrap("1023", "Zero Trust Assessment", {
      up: false,
      data: [{ probe_protocol: "assessment", probe_port: 0, probe_info: "Score: 72/100" }],
      protocol: "assessment",
      port: 0,
    }),
    // Meta: ping (protocol=icmp, port=0)
    wrap("001", "Ping Checker", {
      up: true,
      data: [{ probe_protocol: "icmp", probe_port: 0, probe_info: "Host is up" }],
    }),
    // Meta: OS Detector (protocol=os-detector, port=0)
    wrap("013", "OS Detector", {
      up: true, os: "Linux", osVersion: "5.15",
      data: [{ probe_protocol: "os-detector", probe_port: 0, probe_info: "Detected Linux 5.15" }],
      protocol: "os-detector",
      port: 0,
    }),
    // Meta: ARP (protocol=arp, port=0)
    wrap("026", "ARP Scanner", {
      up: true,
      data: [{ probe_protocol: "arp", probe_port: 0, probe_info: "MAC: aa:bb:cc:dd:ee:ff" }],
      protocol: "arp",
      port: 0,
    }),
    // Meta: Skipped cloud scanner (protocol=api with "Skipped:" in info)
    wrap("020", "Cloud Scanner", {
      up: false,
      data: [{ probe_protocol: "api", probe_port: 0, probe_info: "Skipped: no API key configured" }],
      protocol: "api",
      port: 0,
    }),
  ];

  const res = await concluder.run(results);

  // Only real services should be in the services array
  const servicePorts = res.services.map(s => `${s.protocol}/${s.port}`);
  assert.ok(servicePorts.includes("tcp/22"), "tcp/22 should be in services");
  assert.ok(servicePorts.includes("udp/53"), "udp/53 should be in services");
  assert.ok(servicePorts.includes("tcp/443"), "tcp/443 should be in services");

  // Meta entries should NOT be in services
  assert.ok(!servicePorts.includes("assessment/0"), "assessment/0 should not be in services");
  assert.ok(!servicePorts.includes("icmp/0"), "icmp/0 should not be in services");
  assert.ok(!servicePorts.includes("os-detector/0"), "os-detector/0 should not be in services");
  assert.ok(!servicePorts.includes("arp/0"), "arp/0 should not be in services");
  assert.ok(!servicePorts.includes("api/0"), "api/0 should not be in services");

  assert.equal(res.services.length, 3, "Should have exactly 3 real services");

  // Summary should only reference real services
  assert.ok(!res.summary.includes("zero"), "Summary should not mention zero trust assessment");
  assert.ok(!res.summary.includes("ping/0"), "Summary should not mention ping/0");
  assert.ok(!res.summary.includes("os/0"), "Summary should not mention os/0");
  assert.ok(!res.summary.includes("arp/0"), "Summary should not mention arp/0");

  // Meta entries should still appear in evidence
  const evidenceInfos = res.evidence.map(e => e.info).filter(Boolean);
  assert.ok(evidenceInfos.some(i => /Score.*72/i.test(i)), "Assessment should be in evidence");
  assert.ok(evidenceInfos.some(i => /Host is up/i.test(i)), "Ping should be in evidence");
  assert.ok(evidenceInfos.some(i => /Detected Linux/i.test(i)), "OS Detector should be in evidence");
  assert.ok(evidenceInfos.some(i => /MAC/i.test(i)), "ARP should be in evidence");
  assert.ok(evidenceInfos.some(i => /Skipped/i.test(i)), "Skipped cloud scanner should be in evidence");
});

test("Result Concluder: summary counts only real services", async () => {
  const results = [
    wrap("002", "SSH Scanner", {
      up: true, program: "OpenSSH", version: "8.9",
      data: [{ probe_protocol: "tcp", probe_port: 22, probe_info: "SSH-2.0-OpenSSH_8.9" }],
      type: "ssh",
    }),
    wrap("001", "Ping Checker", {
      up: true,
      data: [{ probe_protocol: "icmp", probe_port: 0, probe_info: "Host is up" }],
    }),
    wrap("013", "OS Detector", {
      up: true, os: "Linux",
      data: [{ probe_protocol: "os-detector", probe_port: 0, probe_info: "Detected Linux" }],
      protocol: "os-detector",
      port: 0,
    }),
  ];

  const res = await concluder.run(results);
  const open = res.services.filter(s => s.status === "open");

  // Only real services contribute to the "Open:" summary
  for (const s of open) {
    assert.notEqual(s.protocol, "icmp", "icmp should not be in open services");
    assert.notEqual(s.protocol, "os-detector", "os-detector should not be in open services");
  }
});
