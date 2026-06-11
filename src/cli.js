#!/usr/bin/env node
/**
 * Honeypot Detector (HPD) — Professional CLI
 *
 * Usage:
 *   hpd init                          Set up environment (RPC URL, etc.)
 *   hpd analyze <address> [options]   Full analysis (static + sim + reputation)
 *   hpd quick <address> [options]     Static-only check (no fork simulation)
 *   hpd simulate <address> <amount>   Run buy/sell simulation on a forked node
 *   hpd ownership <address>           Owner privilege report
 *   hpd liquidity <address>           Liquidity lock status
 *   hpd watch <address>               Live monitoring (re-analyze every N seconds)
 *   hpd demo                          Open interactive demo URL
 *   hpd version                       Show version
 *   hpd help                          Show this help
 *
 * Options:
 *   --network=pharos-mainnet | pharos-testnet
 *   --no-sim                          Skip the forked-chain simulation
 *   --json                            Output raw JSON
 *   --no-color                        Disable colored output
 *   --rpc=<url>                       Override RPC URL for this invocation
 *   --interval=<seconds>              For `watch` command (default 30)
 */

const chalk = require("chalk");
const fs = require("fs");
const path = require("path");
const os = require("os");
const hpd = require("./index");
const { execSync } = require("child_process");

const PKG = require("../package.json");

const USAGE = `
${chalk.bold("Honeypot Detector (HPD)")} v${PKG.version} — smart contract security analysis

${chalk.bold("Usage:")}
  hpd ${chalk.cyan("init")}                            Set up environment (RPC URL, etc.)
  hpd ${chalk.cyan("analyze")} ${chalk.yellow("<address>")} [options]       Full analysis
  hpd ${chalk.cyan("quick")} ${chalk.yellow("<address>")} [options]         Static-only check
  hpd ${chalk.cyan("simulate")} ${chalk.yellow("<address> <amount>")}      Buy/sell simulation
  hpd ${chalk.cyan("ownership")} ${chalk.yellow("<address>")} [options]   Owner privilege report
  hpd ${chalk.cyan("liquidity")} ${chalk.yellow("<address>")} [options]   Liquidity lock status
  hpd ${chalk.cyan("watch")} ${chalk.yellow("<address>")} [options]       Live monitoring
  hpd ${chalk.cyan("demo")}                            Open interactive demo URL
  hpd ${chalk.cyan("version")}                         Show version
  hpd ${chalk.cyan("help")}                            Show this help

${chalk.bold("Options:")}
  ${chalk.green("--network")}=pharos-mainnet | pharos-testnet   Default: pharos-mainnet
  ${chalk.green("--no-sim")}                                    Skip forked-chain simulation
  ${chalk.green("--json")}                                      Output raw JSON
  ${chalk.green("--no-color")}                                  Disable colored output
  ${chalk.green("--rpc")}=${chalk.yellow("<url>")}                            Override RPC URL
  ${chalk.green("--interval")}=${chalk.yellow("<seconds>")}                       For watch (default 30)

${chalk.bold("Networks:")}
  pharos-mainnet    Pharos mainnet (default)
  pharos-testnet    Pharos Atlantic testnet

${chalk.bold("Examples:")}
  ${chalk.gray("$")} hpd analyze 0xdAC17F958D2ee523a2206206994597C13D831ec7
  ${chalk.gray("$")} hpd analyze 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 --no-sim
  ${chalk.gray("$")} hpd quick 0x000000000000000000000000000000000000dEaD --json
  ${chalk.gray("$")} hpd watch 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 --interval=60
`;

// ---------- Config (persistent) ----------
const CONFIG_DIR = path.join(os.homedir(), ".hpd");
const CONFIG_FILE = path.join(CONFIG_DIR, "config.json");

function loadConfig() {
  try {
    if (fs.existsSync(CONFIG_FILE)) {
      return JSON.parse(fs.readFileSync(CONFIG_FILE, "utf-8"));
    }
  } catch (_) {}
  return {};
}

function saveConfig(cfg) {
  fs.mkdirSync(CONFIG_DIR, { recursive: true });
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2));
  fs.chmodSync(CONFIG_FILE, 0o600);
}

function getRpcEnv(networkKey, opts) {
  if (opts.rpc) return opts.rpc;
  const cfg = loadConfig();
  if (cfg.rpc && cfg.rpc[networkKey]) return cfg.rpc[networkKey];
  return process.env[hpd.NETWORKS[networkKey].rpcEnv] || "";
}

// ---------- Args parser ----------
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

function applyOpts(opts) {
  if (opts.color === false || opts["no-color"] === true) {
    chalk.level = 0;
  }
}

// ---------- Output helpers ----------
function colorizeVerdict(verdict) {
  switch (verdict) {
    case "HONEYPOT LIKELY": return chalk.bgRed.white.bold(` ${verdict} `);
    case "HIGH RISK":       return chalk.red.bold(verdict);
    case "CAUTION":         return chalk.yellow.bold(verdict);
    case "SAFE":            return chalk.green.bold(verdict);
    default:                return verdict;
  }
}

function shorten(a) {
  if (!a || a.length < 12) return a || "";
  return a.slice(0, 8) + "…" + a.slice(-6);
}

function printReport(report, asJson = false) {
  if (asJson) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }

  console.log();
  console.log(chalk.bold("Honeypot Detector — Analysis Report"));
  console.log(chalk.gray("─".repeat(60)));
  console.log(`${chalk.gray("Address:    ")} ${report.address}`);
  console.log(`${chalk.gray("Network:    ")} ${report.network}${report.isTestnet ? chalk.gray(" (testnet)") : ""}`);
  console.log(`${chalk.gray("Risk Score: ")} ${chalk.bold(report.riskScore + " / 100")}`);
  console.log(`${chalk.gray("Verdict:    ")} ${colorizeVerdict(report.verdict)}`);
  console.log(`${chalk.gray("Time:       ")} ${report.timestamp}`);
  console.log();
  console.log(`${chalk.bold("Recommendation:")} ${report.recommendation}`);
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
      console.log(`  ${sevColor(`[${f.severity.toUpperCase().padEnd(8)}]`)} ${chalk.bold(f.type.padEnd(22))} — ${f.detail}`);
    }
  }
  if (report.simulation && report.simulation.mode && report.simulation.mode !== "skipped") {
    console.log();
    console.log(chalk.gray(`Simulation mode: ${report.simulation.mode}`));
  }
  console.log();
}

function header(text) {
  console.log();
  console.log(chalk.bold.cyan(text));
  console.log(chalk.gray("─".repeat(text.length)));
}

// ---------- Commands ----------

async function cmdInit(args) {
  header("Initializing HPD");
  const readline = require("readline").createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  // Safe ask(): if stdin closes (EOF, heredoc, paste, etc.) before the
  // user types anything, resolve the pending question with an empty
  // string instead of hanging forever. This makes the init flow
  // robust against paste-bomb scenarios and piped input.
  const ask = (q) =>
    new Promise((res) => {
      let settled = false;
      const onClose = () => {
        if (!settled) {
          settled = true;
          res("");
        }
      };
      readline.once("close", onClose);
      readline.question(q, (answer) => {
        if (!settled) {
          settled = true;
          readline.removeListener("close", onClose);
          res(answer);
        }
      });
    });

  console.log();
  console.log("This will save your RPC URL to: " + chalk.cyan(CONFIG_FILE));
  console.log("(Permissions: 600, only your user can read it)");
  console.log();

  const cfg = loadConfig();
  cfg.rpc = cfg.rpc || {};

  function validateRpc(raw) {
    const s = raw.trim();
    if (!s) return { ok: false, reason: "blank" };
    // Reject anything that doesn't look like an http(s) URL.
    // This catches accidental paste of README command blocks, multi-line
    // input, comments, etc.
    if (!/^https?:\/\/\S+$/i.test(s)) {
      return {
        ok: false,
        reason: "not a URL (must start with http:// or https:// and be on one line)",
      };
    }
    return { ok: true, value: s };
  }

  const mainnetRpc = await ask(`Pharos mainnet RPC URL [leave blank to skip]: `);
  if (mainnetRpc.trim()) {
    const v = validateRpc(mainnetRpc);
    if (!v.ok) {
      console.log(chalk.yellow("  ! Skipped: " + v.reason));
    } else {
      cfg.rpc["pharos-mainnet"] = v.value;
      process.env.PHAROS_MAINNET_RPC = v.value;
      console.log(chalk.green("  ✓ Mainnet RPC saved."));
    }
  }
  const testnetRpc = await ask(`Pharos testnet RPC URL [leave blank to skip]: `);
  if (testnetRpc.trim()) {
    const v = validateRpc(testnetRpc);
    if (!v.ok) {
      console.log(chalk.yellow("  ! Skipped: " + v.reason));
    } else {
      cfg.rpc["pharos-testnet"] = v.value;
      process.env.PHAROS_TESTNET_RPC = v.value;
      console.log(chalk.green("  ✓ Testnet RPC saved."));
    }
  }
  readline.close();

  try {
    saveConfig(cfg);
    console.log();
    console.log(chalk.green("✓ Saved to " + CONFIG_FILE));
    console.log();
    console.log("Try: hpd analyze 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2");
    console.log();
  } catch (err) {
    console.error(chalk.red("✗ Failed to save config: " + err.message));
    console.error(chalk.gray("  You can still use hpd by setting the env var directly:"));
    console.error(chalk.cyan("  export PHAROS_MAINNET_RPC=\"https://rpc.pharos.xyz\""));
    process.exit(1);
  }
}

async function analyzeAddress(address, opts) {
  const network = getNetwork(opts);
  const networkKey = network;
  if (opts.rpc) process.env[hpd.NETWORKS[networkKey].rpcEnv] = opts.rpc;
  const skipSim = opts["no-sim"] === true;
  return hpd.analyzeContract(address, { network, skipSim });
}

async function cmdAnalyze(args) {
  const address = args._[1];
  if (!address) { console.error("Missing <address>"); console.log(USAGE); process.exit(1); }
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    console.error(chalk.red("Invalid address: must be 0x + 40 hex chars"));
    process.exit(1);
  }
  header(`Analyzing ${shorten(address)}`);
  const report = await analyzeAddress(address, args.opts);
  printReport(report, args.opts.json === true);
}

async function cmdQuick(args) {
  const address = args._[1];
  if (!address) { console.error("Missing <address>"); console.log(USAGE); process.exit(1); }
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    console.error(chalk.red("Invalid address: must be 0x + 40 hex chars"));
    process.exit(1);
  }
  header(`Quick check ${shorten(address)}`);
  const network = getNetwork(args.opts);
  if (args.opts.rpc) process.env[hpd.NETWORKS[network].rpcEnv] = args.opts.rpc;
  const report = await hpd.quickCheck(address, { network });
  printReport(report, args.opts.json === true);
}

async function cmdSimulate(args) {
  const address = args._[1];
  const amount = args._[2];
  if (!address || !amount) { console.error("Missing args. Usage: hpd simulate <address> <amount>"); console.log(USAGE); process.exit(1); }
  header(`Simulating ${shorten(address)}`);
  const network = getNetwork(args.opts);
  if (args.opts.rpc) process.env[hpd.NETWORKS[network].rpcEnv] = args.opts.rpc;
  const result = await hpd.simulateTrade(address, amount, { network });
  console.log(JSON.stringify(result, null, 2));
}

async function cmdOwnership(args) {
  const address = args._[1];
  if (!address) { console.error("Missing <address>"); console.log(USAGE); process.exit(1); }
  header(`Ownership ${shorten(address)}`);
  const network = getNetwork(args.opts);
  if (args.opts.rpc) process.env[hpd.NETWORKS[network].rpcEnv] = args.opts.rpc;
  const result = await hpd.checkOwnership(address, { network });
  console.log(JSON.stringify(result, null, 2));
}

async function cmdLiquidity(args) {
  const address = args._[1];
  if (!address) { console.error("Missing <address>"); console.log(USAGE); process.exit(1); }
  header(`Liquidity ${shorten(address)}`);
  const network = getNetwork(args.opts);
  if (args.opts.rpc) process.env[hpd.NETWORKS[network].rpcEnv] = args.opts.rpc;
  const result = await hpd.checkLiquidityLock(address, { network });
  console.log(JSON.stringify(result, null, 2));
}

async function cmdWatch(args) {
  const address = args._[1];
  if (!address) { console.error("Missing <address>"); console.log(USAGE); process.exit(1); }
  const interval = parseInt(args.opts.interval || args.opts.i || "30", 10);
  const network = getNetwork(args.opts);
  if (args.opts.rpc) process.env[hpd.NETWORKS[network].rpcEnv] = args.opts.rpc;

  console.log(chalk.cyan(`Watching ${address} every ${interval}s on ${network}. Ctrl+C to stop.`));
  console.log();

  const tick = async () => {
    const ts = new Date().toLocaleTimeString();
    process.stdout.write(chalk.gray(`[${ts}] `));
    try {
      const report = await hpd.quickCheck(address, { network });
      const colorized = {
        "HONEYPOT LIKELY": chalk.bgRed.white.bold(` ${report.verdict} `),
        "HIGH RISK":       chalk.red.bold(report.verdict),
        "CAUTION":         chalk.yellow.bold(report.verdict),
        "SAFE":            chalk.green.bold(report.verdict),
      }[report.verdict] || report.verdict;
      console.log(`Score ${report.riskScore}/100 · Verdict ${colorized} · ${report.findings.length} finding(s)`);
    } catch (err) {
      console.log(chalk.red("Error: " + err.message));
    }
  };

  tick();
  setInterval(tick, interval * 1000);

  // Keep alive
  await new Promise(() => {});
}

function cmdDemo() {
  const url = "https://ademidun69.github.io/hpd-demo/";
  console.log();
  console.log(chalk.bold("HPD Interactive Demo:"));
  console.log(chalk.cyan(url));
  console.log();
  console.log("Opening in your default browser...");
  try {
    const opener = process.platform === "darwin" ? "open" :
                   process.platform === "win32"  ? "start" : "xdg-open";
    execSync(`${opener} ${url}`, { stdio: "ignore" });
  } catch (_) {
    console.log(chalk.gray("(Could not auto-open. Please copy the URL above.)"));
  }
}

function cmdVersion() {
  console.log(`${PKG.name} v${PKG.version}`);
}

// ---------- Main ----------
async function main() {
  const args = parseArgs(process.argv.slice(2));
  applyOpts(args.opts);

  const cmd = args._[0];

  switch (cmd) {
    case "init":      return cmdInit(args);
    case "analyze":   return cmdAnalyze(args);
    case "a":         return cmdAnalyze(args);
    case "quick":     return cmdQuick(args);
    case "q":         return cmdQuick(args);
    case "simulate":  return cmdSimulate(args);
    case "sim":       return cmdSimulate(args);
    case "ownership": return cmdOwnership(args);
    case "owner":     return cmdOwnership(args);
    case "liquidity": return cmdLiquidity(args);
    case "liq":       return cmdLiquidity(args);
    case "watch":     return cmdWatch(args);
    case "w":         return cmdWatch(args);
    case "demo":      return cmdDemo();
    case "version":   return cmdVersion();
    case "v":         return cmdVersion();
    case "help":      return console.log(USAGE);
    case "h":
    case undefined:    return console.log(USAGE);
    default:
      // Allow bare address: hpd 0xABC... (default to analyze)
      if (/^0x[0-9a-fA-F]{40}$/.test(cmd)) {
        args._.unshift("analyze");
        return cmdAnalyze(args);
      }
      console.error(chalk.red(`Unknown command: ${cmd}`));
      console.log(USAGE);
      process.exit(1);
  }
}

main().catch((err) => {
  console.error(chalk.red("Error: ") + (err.stack || err.message || err));
  process.exit(1);
});
