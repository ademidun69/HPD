/**
 * Honeypot Detector (HPD)
 * Main library entry point.
 *
 * Exposes high-level functions for AI agents to analyze smart contracts
 * for honeypot patterns, rug-pull risk, and malicious behavior.
 */

const { ethers } = require("ethers");
const staticAnalysis = require("./static-analysis");
const simulator = require("./simulator");
const reputation = require("./reputation");
const scorer = require("./scorer");

/**
 * Wrap a JsonRpcProvider's send method with exponential-backoff retry
 * for transient errors (timeout, 5xx, network resets). Helps a lot on
 * mobile networks and against rate-limited public RPCs.
 */
function wrapProviderWithRetry(provider, { maxRetries = 3, baseDelayMs = 500 } = {}) {
  const orig = provider.send.bind(provider);
  provider.send = async (method, params) => {
    let lastErr;
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        return await orig(method, params);
      } catch (err) {
        lastErr = err;
        const msg = (err && err.message) || String(err);
        const isTransient =
          msg.includes("timeout") ||
          msg.includes("TIMEOUT") ||
          msg.includes("ETIMEDOUT") ||
          msg.includes("ECONNRESET") ||
          msg.includes("ECONNREFUSED") ||
          msg.includes("fetch failed") ||
          msg.includes("network does not support ENS") ||
          (err.code && ["TIMEOUT", "ECONNRESET", "ENOTFOUND", "EAI_AGAIN"].includes(err.code));
        if (!isTransient || attempt === maxRetries - 1) break;
        const delay = baseDelayMs * Math.pow(2, attempt);
        await new Promise((r) => setTimeout(r, delay));
      }
    }
    throw lastErr;
  };
  return provider;
}

/**
 * Network configurations.
 * Pharos mainnet is the default; testnet is opt-in.
 */
const NETWORKS = {
  "pharos-mainnet": {
    name: "Pharos Mainnet",
    chainId: 1672,
    rpcEnv: "PHAROS_MAINNET_RPC",
    defaultRpc: "",
    explorer: "https://www.pharosscan.xyz",
    isTestnet: false,
  },
  "pharos-testnet": {
    name: "Pharos Testnet (Atlantic)",
    chainId: 688689,
    rpcEnv: "PHAROS_TESTNET_RPC",
    defaultRpc: "",
    explorer: "https://pharos-testnet.socialscan.io",
    isTestnet: true,
  },
};

/**
 * Resolve a provider for a given network.
 */
function getProvider(networkKey) {
  const config = NETWORKS[networkKey];
  if (!config) {
    throw new Error(
      `Unknown network "${networkKey}". Valid options: ${Object.keys(NETWORKS).join(", ")}`
    );
  }
  const rpc = process.env[config.rpcEnv] || config.defaultRpc;
  if (!rpc) {
    throw new Error(
      `Missing RPC URL. Set the ${config.rpcEnv} environment variable.`
    );
  }
  return { provider: wrapProviderWithRetry(new ethers.JsonRpcProvider(rpc)), config };
}

/**
 * Full contract analysis: static + behavioral + reputation.
 *
 * @param {string} address - Contract address to analyze
 * @param {object} options - { network: "pharos-mainnet" | "pharos-testnet", skipSim: boolean }
 * @returns {Promise<object>} Risk report
 */
async function analyzeContract(address, options = {}) {
  const networkKey = options.network || "pharos-mainnet";
  const { provider, config } = getProvider(networkKey);

  if (!ethers.isAddress(address)) {
    throw new Error(`Invalid contract address: ${address}`);
  }
  const checksum = ethers.getAddress(address);

  // 1. Static analysis
  const staticReport = await staticAnalysis.run(checksum, provider);

  // 2. Behavioral simulation (optional)
  let simReport = null;
  const forkMode = process.env.HPD_FORK_MODE || "auto";
  const shouldSim =
    !options.skipSim && forkMode !== "off" && !staticReport.isERC20Only;

  if (shouldSim) {
    try {
      simReport = await simulator.run(checksum, provider, config);
    } catch (err) {
      simReport = { error: err.message, skipped: true };
    }
  }

  // 3. Reputation
  const repReport = await reputation.run(checksum, provider);

  // 4. Aggregate
  const findings = [
    ...staticReport.findings,
    ...(simReport && !simReport.skipped ? simReport.findings : []),
    ...repReport.findings,
  ];

  const { score, verdict } = scorer.aggregate(findings);

  return {
    address: checksum,
    network: config.name,
    networkKey,
    isTestnet: config.isTestnet,
    explorer: config.explorer,
    riskScore: score,
    verdict,
    findings,
    static: staticReport.summary,
    simulation: simReport ? simReport.summary : null,
    reputation: repReport.summary,
    timestamp: new Date().toISOString(),
    recommendation: scorer.recommend(verdict),
  };
}

/**
 * Fast static-only check. No fork simulation.
 */
async function quickCheck(address, options = {}) {
  return analyzeContract(address, { ...options, skipSim: true });
}

/**
 * Run a buy/sell simulation on a forked node.
 */
async function simulateTrade(address, amountIn, options = {}) {
  const networkKey = options.network || "pharos-mainnet";
  const { provider, config } = getProvider(networkKey);
  if (!ethers.isAddress(address)) {
    throw new Error(`Invalid contract address: ${address}`);
  }
  return simulator.runTrade(
    ethers.getAddress(address),
    amountIn,
    provider,
    config
  );
}

/**
 * Owner privilege report.
 */
async function checkOwnership(address, options = {}) {
  const networkKey = options.network || "pharos-mainnet";
  const { provider, config } = getProvider(networkKey);
  if (!ethers.isAddress(address)) {
    throw new Error(`Invalid contract address: ${address}`);
  }
  return reputation.ownership(ethers.getAddress(address), provider);
}

/**
 * Liquidity lock check.
 */
async function checkLiquidityLock(address, options = {}) {
  const networkKey = options.network || "pharos-mainnet";
  const { provider, config } = getProvider(networkKey);
  if (!ethers.isAddress(address)) {
    throw new Error(`Invalid contract address: ${address}`);
  }
  return reputation.liquidityLock(ethers.getAddress(address), provider);
}

module.exports = {
  NETWORKS,
  analyzeContract,
  quickCheck,
  simulateTrade,
  checkOwnership,
  checkLiquidityLock,
};
