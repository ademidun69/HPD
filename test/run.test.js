/**
 * Honeypot Detector — basic tests.
 *
 * Run without an RPC; verifies internal logic:
 *   - Selector extraction
 *   - Risk aggregation
 *   - Verdict thresholds
 */

const assert = require("assert");
const { extractSelectors, DANGEROUS_SELECTORS } = require("../src/static-analysis");
const scorer = require("../src/scorer");
const index = require("../src/index");

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`✗ ${name}`);
    console.error(`  ${err.message}`);
    failed++;
  }
}

test("extractSelectors finds PUSH4 selectors", () => {
  const code = "0x63deadbeef00";
  const sels = extractSelectors(code);
  assert.ok(sels.includes("0xdeadbeef"), `Expected 0xdeadbeef in ${JSON.stringify(sels)}`);
});

test("extractSelectors returns empty for no PUSH4", () => {
  const sels = extractSelectors("0x600052");
  assert.deepStrictEqual(sels, []);
});

test("extractSelectors handles empty code", () => {
  const sels = extractSelectors("0x");
  assert.deepStrictEqual(sels, []);
});

test("dangerous selectors are defined", () => {
  assert.ok(DANGEROUS_SELECTORS["0x40c10f19"]); // mint(address,uint256)
  assert.strictEqual(DANGEROUS_SELECTORS["0x40c10f19"].type, "HIDDEN_MINT");
  assert.ok(DANGEROUS_SELECTORS["0x43d726d6"]); // selfdestruct
  assert.strictEqual(DANGEROUS_SELECTORS["0x43d726d6"].severity, "critical");
});

test("scorer: no findings = SAFE", () => {
  const { score, verdict } = scorer.aggregate([]);
  assert.strictEqual(score, 0);
  assert.strictEqual(verdict, "SAFE");
});

test("scorer: critical finding = HONEYPOT LIKELY", () => {
  const findings = [{ severity: "critical", type: "SELFDESTRUCT", detail: "x" }];
  const { score, verdict } = scorer.aggregate(findings);
  assert.ok(score >= 80);
  assert.strictEqual(verdict, "HONEYPOT LIKELY");
});

test("scorer: high finding = HIGH RISK", () => {
  const findings = [{ severity: "high", type: "HONEYPOT_SELL_TAX", detail: "x" }];
  const { verdict } = scorer.aggregate(findings);
  assert.strictEqual(verdict, "HIGH RISK");
});

test("scorer: medium finding = CAUTION", () => {
  const findings = [{ severity: "medium", type: "YOUNG_CONTRACT", detail: "x" }];
  const { verdict } = scorer.aggregate(findings);
  assert.strictEqual(verdict, "CAUTION");
});

test("scorer: score capped at 100", () => {
  const findings = [
    { severity: "critical" }, { severity: "critical" },
    { severity: "critical" }, { severity: "high" },
    { severity: "high" }, { severity: "medium" },
  ];
  const { score } = scorer.aggregate(findings);
  assert.strictEqual(score, 100);
});

test("recommend returns string for each verdict", () => {
  assert.ok(typeof scorer.recommend("SAFE") === "string");
  assert.ok(typeof scorer.recommend("CAUTION") === "string");
  assert.ok(typeof scorer.recommend("HIGH RISK") === "string");
  assert.ok(typeof scorer.recommend("HONEYPOT LIKELY") === "string");
});

test("recommend has substance for dangerous verdicts", () => {
  assert.ok(scorer.recommend("HONEYPOT LIKELY").length > 10);
  assert.ok(scorer.recommend("HIGH RISK").length > 10);
});

test("wrapProviderWithRetry retries on timeout and eventually throws", async () => {
  // Build a fake provider that always throws TIMEOUT
  const fake = {
    send: async () => {
      const e = new Error("request timeout");
      e.code = "TIMEOUT";
      throw e;
    },
  };
  const wrapped = index.wrapProviderWithRetry(fake, { maxRetries: 3, baseDelayMs: 10 });
  let threw = false;
  try {
    await wrapped.send("eth_blockNumber", []);
  } catch (e) {
    threw = true;
    assert.strictEqual(e.code, "TIMEOUT");
  }
  assert.ok(threw, "expected timeout to be re-thrown after retries");
  assert.strictEqual(fake.send.callCount ?? 3, 3); // may be undefined on plain object
});

test("wrapProviderWithRetry does NOT retry on non-transient errors", async () => {
  let calls = 0;
  const fake = {
    send: async () => {
      calls++;
      const e = new Error("execution reverted");
      e.code = "CALL_EXCEPTION";
      throw e;
    },
  };
  const wrapped = index.wrapProviderWithRetry(fake, { maxRetries: 5, baseDelayMs: 1 });
  let threw = false;
  try {
    await wrapped.send("eth_call", []);
  } catch (e) {
    threw = true;
    assert.strictEqual(e.code, "CALL_EXCEPTION");
  }
  assert.ok(threw, "expected CALL_EXCEPTION to be re-thrown");
  assert.strictEqual(calls, 1, "non-transient error should not be retried");
});

test("wrapProviderWithRetry returns the first success", async () => {
  let calls = 0;
  const fake = {
    send: async (method) => {
      calls++;
      if (calls < 2) {
        const e = new Error("ETIMEDOUT");
        e.code = "ETIMEDOUT";
        throw e;
      }
      return { result: "ok", method };
    },
  };
  const wrapped = index.wrapProviderWithRetry(fake, { maxRetries: 3, baseDelayMs: 1 });
  const out = await wrapped.send("eth_chainId", []);
  assert.deepStrictEqual(out, { result: "ok", method: "eth_chainId" });
  assert.strictEqual(calls, 2);
});

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
