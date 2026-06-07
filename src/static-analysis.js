/**
 * Static analysis module.
 * Inspects bytecode and function selectors for known dangerous patterns.
 */

const { ethers } = require("ethers");

// Function-selector signatures of well-known dangerous functions.
const DANGEROUS_SELECTORS = {
  // Hidden mint
  "0x429b62e5": { name: "HIDDEN_MINT_OWNER", severity: "high", type: "HIDDEN_MINT", detail: "Owner-only mint function detected" },
  "0x40c10f19": { name: "MINT_OWNER", severity: "high", type: "HIDDEN_MINT", detail: "mint(address,uint256) is owner-only" },
  "0x4f6e3753": { name: "OWNABLE_MINT", severity: "medium", type: "HIDDEN_MINT", detail: "Owner mint capability found" },
  "0xa2c44ee7": { name: "OWNER_BURN_ANY", severity: "high", type: "OWNER_BURN", detail: "Owner can burn tokens from any holder" },

  // Selfdestruct
  "0x43d726d6": { name: "SELFDESTRUCT", severity: "critical", type: "SELFDESTRUCT", detail: "Contract can self-destruct and drain funds" },

  // Pause / blacklist
  "0x8456cb59": { name: "PAUSE", severity: "medium", type: "PAUSABLE", detail: "Transfers can be paused by owner" },
  "0x5c975abb": { name: "PAUSED", severity: "low", type: "PAUSABLE", detail: "Paused state readable" },
  "0xe4997f0a": { name: "BLACKLIST", severity: "high", type: "BLACKLIST", detail: "Owner can blacklist addresses from trading" },
  "0x2f4f5f0a": { name: "IS_BLACKLISTED", severity: "medium", type: "BLACKLIST", detail: "Blacklist lookup present" },
  "0xf0f44260": { name: "SET_BLACKLIST", severity: "high", type: "BLACKLIST", detail: "Setter for blacklist" },

  // Owner withdraw
  "0x3ccfd60b": { name: "WITHDRAW_ETH", severity: "high", type: "OWNER_WITHDRAW", detail: "Owner can withdraw all ETH" },
  "0xf3fef3a3": { name: "WITHDRAW_TOKENS", severity: "high", type: "OWNER_WITHDRAW", detail: "Owner can withdraw arbitrary tokens" },
  "0xdbd4c27f": { name: "RESCUE_TOKENS", severity: "high", type: "OWNER_WITHDRAW", detail: "Rescue function (often used to drain user tokens)" },
  "0x9e281a98": { name: "RESCUE_ETH", severity: "high", type: "OWNER_WITHDRAW", detail: "Rescue ETH function" },

  // Fee / tax manipulation
  "0x902d55a5": { name: "SET_FEE", severity: "medium", type: "FEE_MANIPULATION", detail: "Buy/sell fees can be changed by owner" },
  "0x69fef0d2": { name: "SET_TAX", severity: "medium", type: "FEE_MANIPULATION", detail: "Tax rate mutable by owner" },
  "0xc0248b50": { name: "SET_SELL_TAX", severity: "high", type: "FEE_MANIPULATION", detail: "Sell tax is mutable" },

  // Proxy upgrade risks
  "0x3659cfe6": { name: "UPGRADE_TO", severity: "medium", type: "PROXY_UPGRADE", detail: "Implementation can be upgraded" },
  "0x4f1ef286": { name: "UPGRADE_TO_AND_CALL", severity: "medium", type: "PROXY_UPGRADE", detail: "Implementation upgrade with call" },
  "0x8f283970": { name: "CHANGE_ADMIN", severity: "low", type: "PROXY_UPGRADE", detail: "Admin changeable" },

  // Trading controls
  "0x8f70cc4b": { name: "SET_MAX_WALLET", severity: "medium", type: "MAX_WALLET", detail: "Max wallet size can be changed" },
  "0xf7c618c1": { name: "SET_MAX_TX", severity: "medium", type: "MAX_TX", detail: "Max transaction size can be changed" },
  "0x49bd7378": { name: "ENABLE_TRADING", severity: "low", type: "TRADING_TOGGLE", detail: "Trading can be toggled on/off" },
  "0x8a8c523c": { name: "SET_TRADING", severity: "medium", type: "TRADING_TOGGLE", detail: "Trading state can be changed" },
};

const ERC20_SELECTORS = [
  "0x06fdde03", // name
  "0x95d89b41", // symbol
  "0x313ce567", // decimals
  "0x18160ddd", // totalSupply
  "0x70a08231", // balanceOf
  "0xa9059cbb", // transfer
  "0xdd62ed3e", // allowance
  "0x095ea7b3", // approve
  "0x23b872dd", // transferFrom
];

async function run(address, provider) {
  const findings = [];
  const code = await provider.getCode(address);

  if (code === "0x" || code === "0x0") {
    findings.push({
      type: "NOT_CONTRACT",
      severity: "critical",
      detail: "Address has no contract code. It is an EOA or a non-deployed address.",
    });
    return {
      findings,
      summary: { hasCode: false, codeSize: 0, isERC20Only: false },
    };
  }

  const codeSize = (code.length - 2) / 2;
  const summary = {
    hasCode: true,
    codeSize,
    isERC20Only: false,
    detectedSelectors: [],
    dangerousSelectors: [],
  };

  const selectors = extractSelectors(code);
  summary.detectedSelectors = selectors;

  for (const sel of selectors) {
    if (DANGEROUS_SELECTORS[sel]) {
      const d = DANGEROUS_SELECTORS[sel];
      findings.push({ ...d, selector: sel });
      summary.dangerousSelectors.push(sel);
    }
  }

  const hasAllErc20 = ERC20_SELECTORS.every((s) => selectors.includes(s));
  if (hasAllErc20 && summary.dangerousSelectors.length === 0) {
    summary.isERC20Only = true;
  }

  if (codeSize < 200) {
    findings.push({
      type: "TINY_CONTRACT",
      severity: "low",
      detail: `Contract bytecode is very small (${codeSize} bytes). May be a proxy or stub.`,
    });
  }

  return { findings, summary };
}

/**
 * Extract all 4-byte selectors from EVM bytecode.
 * Scans for PUSH4 (0x63) opcodes and reads the next 4 bytes.
 */
function extractSelectors(code) {
  const hex = code.startsWith("0x") ? code.slice(2) : code;
  if (hex.length === 0) return [];
  const bytes = Buffer.from(hex, "hex");
  const selectors = new Set();

  for (let i = 0; i < bytes.length - 4; i++) {
    if (bytes[i] === 0x63) {
      const sel =
        "0x" +
        bytes[i + 1].toString(16).padStart(2, "0") +
        bytes[i + 2].toString(16).padStart(2, "0") +
        bytes[i + 3].toString(16).padStart(2, "0") +
        bytes[i + 4].toString(16).padStart(2, "0");
      if (/^0x[0-9a-f]{8}$/.test(sel)) {
        selectors.add(sel);
      }
    }
  }

  return Array.from(selectors);
}

module.exports = { run, extractSelectors, DANGEROUS_SELECTORS };
