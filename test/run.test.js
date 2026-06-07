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

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed > 0 ? 1 : 0);
