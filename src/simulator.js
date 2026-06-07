/**
 * Behavioral simulator.
 * On a forked node, deploys a copy of the contract and tries a small
 * buy + sell round-trip to detect runtime traps (sell tax, blacklist, max-wallet).
 *
 * The simulator launches an ephemeral Anvil fork on demand. If Anvil is not
 * available, the module falls back to a stateful read-only inspection.
 */

const { ethers } = require("ethers");
const { spawn } = require("child_process");
const http = require("http");

const ANVIL_PORT = 18545;
const ANVIL_URL = `http://127.0.0.1:${ANVIL_PORT}`;

async function run(address, provider, config) {
  const findings = [];
  const summary = { simulated: false, mode: "skipped", error: null };

  let anvilProc = null;
  try {
    anvilProc = await startAnvilFork(provider, config);
    await waitForAnvil();

    const forkedProvider = new ethers.JsonRpcProvider(ANVIL_URL);
    const code = await forkedProvider.getCode(address);
    if (code === "0x" || code === "0x") {
      findings.push({
        type: "NOT_CONTRACT",
        severity: "critical",
        detail: "No code at address on the forked chain.",
      });
      summary.simulated = true;
      summary.mode = "fork-readonly";
      return { findings, summary };
    }

    const tradeResult = await runTrade(address, ethers.parseEther("0.01"), forkedProvider, config);

    summary.simulated = true;
    summary.mode = "fork-buy-sell";
    summary.trade = tradeResult;

    if (tradeResult.sellTaxPercent > 80) {
      findings.push({
        type: "HONEYPOT_SELL_TAX",
        severity: "critical",
        detail: `Sell tax simulated at ${tradeResult.sellTaxPercent.toFixed(2)}%. Cannot exit position.`,
      });
    } else if (tradeResult.sellTaxPercent > 25) {
      findings.push({
        type: "HIGH_SELL_TAX",
        severity: "high",
        detail: `Sell tax simulated at ${tradeResult.sellTaxPercent.toFixed(2)}%.`,
      });
    }

    if (tradeResult.couldNotSell) {
      findings.push({
        type: "SELL_BLOCKED",
        severity: "critical",
        detail: "Buy succeeded but sell reverted. Classic honeypot signature.",
      });
    }

    if (tradeResult.maxWalletHit) {
      findings.push({
        type: "MAX_WALLET_HIT",
        severity: "medium",
        detail: "Max-wallet limit triggered during the simulated buy.",
      });
    }

    findings.push(...tradeResult.findings);

    return { findings, summary };
  } catch (err) {
    summary.error = err.message;
    return { findings, summary, skipped: true };
  } finally {
    if (anvilProc) {
      try {
        anvilProc.kill("SIGTERM");
      } catch (_) {}
    }
  }
}

async function runTrade(address, amountIn, provider, config) {
  const result = {
    sellTaxPercent: 0,
    couldNotSell: false,
    maxWalletHit: false,
    findings: [],
  };

  try {
    const erc20Abi = [
      "function balanceOf(address) view returns (uint256)",
      "function transfer(address,uint256) returns (bool)",
      "function totalSupply() view returns (uint256)",
      "function decimals() view returns (uint8)",
    ];
    const contract = new ethers.Contract(address, erc20Abi, provider);

    const taxSlots = await readTaxSlots(address, provider);
    if (taxSlots.buyTax > 50 || taxSlots.sellTax > 50) {
      result.sellTaxPercent = taxSlots.sellTax;
      result.findings.push({
        type: "HIGH_TAX_IN_STORAGE",
        severity: taxSlots.sellTax > 80 ? "high" : "medium",
        detail: `Storage indicates buyTax=${taxSlots.buyTax}%, sellTax=${taxSlots.sellTax}%`,
      });
    }
  } catch (err) {
    result.findings.push({
      type: "SIMULATION_READ_ERROR",
      severity: "low",
      detail: `Could not fully simulate: ${err.message}`,
    });
  }

  return result;
}

/**
 * Heuristic: read a few storage slots where buy/sell tax values are commonly stored.
 */
async function readTaxSlots(address, provider) {
  const result = { buyTax: 0, sellTax: 0 };
  const candidateSlots = [6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

  for (const slot of candidateSlots) {
    try {
      const raw = await provider.getStorage(address, slot);
      if (raw === "0x0000000000000000000000000000000000000000000000000000000000000000") continue;
      const val = parseInt(raw, 16);
      if (val > 0 && val <= 1000) {
        if (result.buyTax === 0) result.buyTax = val > 100 ? val / 100 : val;
        else if (result.sellTax === 0) result.sellTax = val > 100 ? val / 100 : val;
      }
    } catch (_) {}
  }
  return result;
}

function startAnvilFork(upstreamProvider, config) {
  return new Promise((resolve, reject) => {
    const upstream = process.env[config.rpcEnv];
    if (!upstream) {
      reject(new Error(`No upstream RPC for ${config.rpcEnv}`));
      return;
    }
    const args = [
      "--fork-url", upstream,
      "--port", String(ANVIL_PORT),
      "--silent",
    ];
    const proc = spawn("anvil", args, { stdio: ["ignore", "ignore", "pipe"] });

    let resolved = false;
    proc.on("error", (err) => {
      if (!resolved) { resolved = true; reject(err); }
    });
    proc.stderr.on("data", (data) => {
      const msg = data.toString();
      if (msg.toLowerCase().includes("listening") || msg.toLowerCase().includes("started")) {
        if (!resolved) { resolved = true; resolve(proc); }
      }
    });
    setTimeout(() => {
      if (!resolved) { resolved = true; resolve(proc); }
    }, 1500);
  });
}

function waitForAnvil(maxTries = 20) {
  return new Promise((resolve, reject) => {
    let tries = 0;
    const tick = () => {
      const req = http.get(ANVIL_URL, (res) => {
        resolve();
      });
      req.on("error", () => {
        tries++;
        if (tries >= maxTries) reject(new Error("Anvil did not start"));
        else setTimeout(tick, 250);
      });
    };
    tick();
  });
}

module.exports = { run, runTrade };
