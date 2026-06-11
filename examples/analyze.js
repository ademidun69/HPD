#!/usr/bin/env node
/**
 * analyze.js — example: analyze one or more addresses as a library user.
 *
 * Usage:
 *   PHAROS_MAINNET_RPC="https://rpc.pharos.xyz" node examples/analyze.js [address1] [address2] ...
 *
 * If no addresses are given, defaults to a small set of demo addresses
 * (a real Pharos mainnet contract and a known EOA).
 */

const hpd = require("../src/index");

const DEFAULT_ADDRESSES = [
  "0x51e2A24742Db77604B881d6781Ee16B5b8fcBE29", // LINK on Pharos (real contract)
  "0xc9A0B63d91c2A808dD631d031f037944fedDaA12", // EOA, not a contract on Pharos
];

function shortenAddress(a) {
  return a.slice(0, 8) + "…" + a.slice(-6);
}

(async () => {
  const addrs = process.argv.slice(2);
  const targets = addrs.length ? addrs : DEFAULT_ADDRESSES;
  const network = process.env.HPD_NETWORK || "pharos-mainnet";

  for (const addr of targets) {
    console.log("\n" + "=".repeat(60));
    console.log("Analyzing:", addr, "(" + shortenAddress(addr) + ")");
    console.log("Network:  ", network);
    console.log("=".repeat(60));
    try {
      const report = await hpd.analyzeContract(addr, { network });
      console.log("Risk Score:    ", report.riskScore, "/ 100");
      console.log("Verdict:       ", report.verdict);
      console.log("Findings (" + report.findings.length + "):");
      for (const f of report.findings) {
        console.log("  [" + f.severity.toUpperCase() + "]", f.type.padEnd(22), "-", f.detail);
      }
      console.log("Recommendation:", report.recommendation);
    } catch (err) {
      console.error("Error analyzing", addr + ":", err.message);
    }
  }
})().catch((err) => {
  console.error("Fatal:", err.message);
  process.exit(1);
});
