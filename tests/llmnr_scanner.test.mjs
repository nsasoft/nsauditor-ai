import assert from "node:assert";
import llmnrScanner from "../plugins/llmnr_scanner.mjs";

const TEST_HOST = "testhost"; // Use a non-existent host for basic test

async function main() {
  const result = await llmnrScanner.run(TEST_HOST, 0, { timeoutMs: 1000 });
  assert(result, "Result should be defined");
  assert(Array.isArray(result.data), "Result data should be an array");
  assert(result.data.length > 0, "Result data should have at least one entry");
  assert(result.data[0].probe_protocol === "llmnr", "Protocol should be llmnr");
  assert(result.data[0].probe_port === 5355, "Port should be 5355");
  console.log("LLMNR Scanner basic test passed.");
}

main().catch(e => {
  console.error("LLMNR Scanner test failed:", e);
  process.exit(1);
});
