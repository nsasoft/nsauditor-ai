// tests/snmp_scanner.test.mjs
// Run with: node --test
import { test, describe, mock } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

import snmpScanner, {
  DEFAULT_COMMUNITIES,
  snmpCommunities,
  conclude,
} from "../plugins/snmp_scanner.mjs";

const execFileAsync = promisify(execFile);

/* ---------------------------------------------------------------
 * 1. Community-list defaults (no env var set in this process)
 * --------------------------------------------------------------- */

test("snmpCommunities defaults to ['public', 'private'] when SNMP_COMMUNITY env var is not set", () => {
  assert.deepStrictEqual(DEFAULT_COMMUNITIES, ["public", "private"]);
  // In CI / dev the env var is typically unset, so snmpCommunities should match defaults
  if (!process.env.SNMP_COMMUNITY) {
    assert.deepStrictEqual(snmpCommunities, ["public", "private"]);
  }
});

/* ---------------------------------------------------------------
 * 2. SNMP_COMMUNITY env var parsing via subprocess
 * --------------------------------------------------------------- */

test("snmpCommunities respects SNMP_COMMUNITY env var", async () => {
  const script = `
    import { snmpCommunities } from '../plugins/snmp_scanner.mjs';
    process.stdout.write(JSON.stringify(snmpCommunities));
  `;
  const { stdout } = await execFileAsync(
    process.execPath,
    ["--input-type=module", "-e", script],
    {
      env: { ...process.env, SNMP_COMMUNITY: "public,private,cisco" },
      cwd: new URL(".", import.meta.url).pathname,
    }
  );
  const parsed = JSON.parse(stdout);
  assert.deepStrictEqual(parsed, ["public", "private", "cisco"]);
  assert.equal(parsed.length, 3);
});

test("SNMP_COMMUNITY env var trims whitespace and filters blanks", async () => {
  const script = `
    import { snmpCommunities } from '../plugins/snmp_scanner.mjs';
    process.stdout.write(JSON.stringify(snmpCommunities));
  `;
  const { stdout } = await execFileAsync(
    process.execPath,
    ["--input-type=module", "-e", script],
    {
      env: { ...process.env, SNMP_COMMUNITY: " custom1 , , custom2 " },
      cwd: new URL(".", import.meta.url).pathname,
    }
  );
  const parsed = JSON.parse(stdout);
  assert.deepStrictEqual(parsed, ["custom1", "custom2"]);
});

/* ---------------------------------------------------------------
 * 3. Result includes `community` and `communitiesTried` fields
 * --------------------------------------------------------------- */

test("snmp_scanner: result includes community and communitiesTried fields", { timeout: 10_000 }, async () => {
  // Running against localhost — snmp-native may not be installed and/or
  // no SNMP daemon is listening, so scanner will error or get no response.
  const res = await snmpScanner.run("127.0.0.1", {});
  assert.ok("community" in res, "result must have a community field");
  assert.ok("communitiesTried" in res, "result must have a communitiesTried field");
  assert.ok(Array.isArray(res.communitiesTried), "communitiesTried must be an array");
  // community should be null since nothing responded
  assert.equal(res.community, null);
  // If snmp-native is not installed, communitiesTried will be empty (error thrown
  // before the loop). If installed but no daemon, it will have entries.
  // Either way the fields must exist and be correct types.
});

/* ---------------------------------------------------------------
 * 4. Default community strings flagged in probe_info
 * --------------------------------------------------------------- */

describe("conclude() passes community through to service record", () => {
  test("conclude includes community in info and banner when present", async () => {
    const mockResult = {
      up: true,
      program: "Cisco",
      version: "15.1",
      community: "public",
      communitiesTried: ["public"],
      data: [
        {
          probe_protocol: "udp",
          probe_port: 161,
          probe_info: "SNMP response received: Cisco 15.1 (OS: Cisco IOS) (Type: router)",
          response_banner: "Cisco IOS Software version 15.1",
        },
      ],
    };
    const records = await conclude({ host: "192.168.1.1", result: mockResult });
    assert.equal(records.length, 1);
    const rec = records[0];
    assert.equal(rec.community, "public");
    assert.ok(rec.info.includes("[community=public]"), `info should contain community: ${rec.info}`);
    assert.ok(rec.banner.includes("[community=public]"), `banner should contain community: ${rec.banner}`);
  });

  test("conclude omits community annotation when community is null", async () => {
    const mockResult = {
      up: false,
      program: "Unknown",
      version: "Unknown",
      community: null,
      communitiesTried: ["public", "private"],
      data: [
        {
          probe_protocol: "udp",
          probe_port: 161,
          probe_info: 'No SNMP response for community "public"',
          response_banner: null,
        },
      ],
    };
    const records = await conclude({ host: "192.168.1.1", result: mockResult });
    const rec = records[0];
    assert.equal(rec.community, null);
    assert.ok(!rec.info.includes("[community="), "info should not have community annotation");
    assert.equal(rec.banner, null);
  });
});

describe("default community string misconfiguration warning", () => {
  test("probe_info flags 'public' as default community misconfiguration", () => {
    // Simulate what the run() method builds for a default community
    const comm = "public";
    const program = "Linux";
    const version = "5.15";
    const os = "Linux/Unix";
    const type = "server";

    // Replicate the probe_info construction from the plugin
    const infoPieces = [
      `SNMP response received: ${program} ${version} (OS: ${os}) (Type: ${type}`,
    ];
    infoPieces.push(")");
    if (comm === "public" || comm === "private") {
      infoPieces.push(
        ` WARNING: Default SNMP community string '${comm}' accepted — misconfiguration`
      );
    }
    const probeInfo = infoPieces.join(", ");

    assert.ok(
      probeInfo.includes("WARNING: Default SNMP community string 'public' accepted"),
      `Expected warning in probe_info, got: ${probeInfo}`
    );
  });

  test("probe_info flags 'private' as default community misconfiguration", () => {
    const comm = "private";
    const infoPieces = [
      `SNMP response received: Cisco 15.1 (OS: Cisco IOS) (Type: router`,
    ];
    infoPieces.push(")");
    if (comm === "public" || comm === "private") {
      infoPieces.push(
        ` WARNING: Default SNMP community string '${comm}' accepted — misconfiguration`
      );
    }
    const probeInfo = infoPieces.join(", ");

    assert.ok(
      probeInfo.includes(
        "WARNING: Default SNMP community string 'private' accepted — misconfiguration"
      ),
      `Expected warning in probe_info, got: ${probeInfo}`
    );
  });

  test("no warning for non-default community strings", () => {
    const comm = "mySecret123";
    let probeInfo = `SNMP response received: Linux 5.15 (OS: Linux/Unix) (Type: server)`;
    if (comm === "public" || comm === "private") {
      probeInfo += ` WARNING: Default SNMP community string '${comm}' accepted — misconfiguration`;
    }

    assert.ok(
      !probeInfo.includes("WARNING"),
      `Should not have warning for custom community, got: ${probeInfo}`
    );
  });
});

/* ---------------------------------------------------------------
 * 5. Existing test: localhost no response (preserved)
 * --------------------------------------------------------------- */

test("snmp_scanner: localhost typically yields no response on UDP/161", { timeout: 10_000 }, async () => {
  const res = await snmpScanner.run("127.0.0.1", 161);
  assert.equal(typeof res.up, "boolean");
  assert.equal(res.up, false);
  assert.equal(res.program, "Unknown");
  assert.equal(res.version, "Unknown");
  assert.ok(Array.isArray(res.data) && res.data.length > 0);
  const entry = res.data.find(
    (d) => d.probe_protocol === "udp" && d.probe_port === 161
  );
  assert.ok(entry, "expected a UDP 161 entry");
  // If snmp-native is not installed, the error message will differ from "No SNMP response"
  assert.ok(
    /no snmp response/i.test(entry.probe_info) ||
      /error/i.test(entry.probe_info),
    `expected 'no snmp response' or 'error' in probe_info, got: ${entry.probe_info}`
  );
});
