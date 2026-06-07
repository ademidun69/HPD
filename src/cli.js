#!/usr/bin/env node
/**
 * Honeypot Detector (HPD) CLI.
 *
 * Usage:
 *   hpd analyze <address> [--network=pharos-mainnet|pharos-testnet] [--no-sim]
 *   hpd quick <address>   [--network=pharos-mainnet|pharos-testnet]
 *   hpd simulate <address> <amountIn> [--network=pharos-mainnet|pharos-testnet]
 *   hpd ownership <address> [--network=pharos-mainnet|pharos-testnet]
 */

const chalk = require("chalk");
const hpd = require("./index");

const USAGE = `
Honeypot Detector (HPD) — smart contract security analysis

Commands:
  analyze <address> [--network=<net>] [--no-sim]   Full analysis
  quick <address>   [--network=<net>]              Static-only check
  simulate <address> <amountIn> [--network=<net>]  Buy/sell simulation
  ownership <address> [--network=<net>]            Owner privilege report

Networks:
  pharos-mainnet   (default)
  pharos-testnet   Pharos Atlantic testnet
`;

function parseArgs(argv) {
  const args = { _: [], opts: {} };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--")) {
      const [k, v] = a.slice(2).split("=");
      args.opts[k] = v === undefined ? true : v;
    } else {
      args._.push(a);
    }
  }
  return args;
}

function getNetwork(opts) {
  const net = opts.network || "pharos-mainnet";
  if (!hpd.NETWORKS[net]) {
    console.error(chalk.red(`Unknown network: ${net}`));
    console.error(`Valid: ${Object.keys(hpd.NETWORKS).join(", ")}`);
    process.exit(1);
  }
  return net;
}

function colorizeVerdict(verdict) {
  switch (verdict) {
    case "HONEYPOT LIKELY": return chalk.bgRed.white.bold(` ${verdict} `);
    case "HIGH RISK":       return chalk.red.bold(verdict);
    case "CAUTION":         return chalk.yellow.bold(verdict);
    case "SAFE":            return chalk.green.bold(verdict);
    default:                return verdict;
  }
}

function printReport(report) {
  console.log();
  console.log(chalk.bold("Honeypot Detector — Analysis Report"));
  console.log(chalk.gray("─".repeat(60)));
  console.log(`Address:    ${report.address}`);
  console.log(`Network:    ${report.network}${report.isTestnet ? chalk.gray(" (testnet)") : ""}`);
  console.log(`Risk Score: ${chalk.bold(report.riskScore + " / 100")}`);
  console.log(`Verdict:    ${colorizeVerdict(report.verdict)}`);
  console.log(`Recommendation: ${report.recommendation}`);
  console.log();
  if (report.findings.length === 0) {
    console.log(chalk.green("✓ No findings detected."));
  } else {
    console.log(chalk.bold("Findings:"));
    for (const f of report.findings) {
      const sevColor = {
        critical: chalk.bgRed.white,
        high: chalk.red,
        medium: chalk.yellow,
        low: chalk.gray,
      }[f.severity] || chalk.white;
      console.log(`  ${sevColor(`[${f.severity.toUpperCase()}]`)} ${chalk.bold(f.type)} — ${f.detail}`);
    }
  }
  console.log();
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0];
  const address = args._[1];
  const network = getNetwork(args.opts);

  if (cmd === "analyze") {
    if (!address) { console.error("Missing <address>"); console.error(USAGE); process.exit(1); }
    const skipSim = args.opts["no-sim"] === true;
    const report = await hpd.analyzeContract(address, { network, skipSim });
    printReport(report);
  } else if (cmd === "quick") {
    if (!address) { console.error("Missing <address>"); console.error(USAGE); process.exit(1); }
    const report = await hpd.quickCheck(address, { network });
    printReport(report);
  } else if (cmd === "simulate") {
    if (!address || !args._[2]) { console.error("Missing args"); console.error(USAGE); process.exit(1); }
    const amountIn = args._[2];
    const result = await hpd.simulateTrade(address, amountIn, { network });
    console.log(JSON.stringify(result, null, 2));
  } else if (cmd === "ownership") {
    if (!address) { console.error("Missing <address>"); console.error(USAGE); process.exit(1); }
    const result = await hpd.checkOwnership(address, { network });
    console.log(JSON.stringify(result, null, 2));
  } else {
    console.log(USAGE);
  }
}

main().catch((err) => {
  console.error(chalk.red("Error: ") + err.message);
  process.exit(1);
});
