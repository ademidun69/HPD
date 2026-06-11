---
name: honeypot-detector
description: A professional smart contract security analysis skill for AI agents. Performs static analysis, behavioral simulation, and risk scoring on EVM smart contracts to detect honeypots, rug pulls, hidden mints, owner-only withdrawals, and other malicious patterns. Supports Pharos mainnet (default) and Pharos testnet.
---

# Honeypot Detector (HPD)

A professional smart contract security analysis skill that empowers AI agents to evaluate the trustworthiness of EVM smart contracts before any interaction takes place.

## What It Does

Honeypot Detector combines three layers of analysis to produce a single, easy-to-interpret risk verdict:

1. **Static Analysis** — Scans deployed bytecode and ABI for high-risk function signatures such as `selfdestruct`, hidden `mint`, owner-only `withdraw`, pausable transfers, blacklist mechanisms, and proxy patterns that allow silent upgrades.
2. **Behavioral Simulation** — Forks the target chain locally, deploys the contract, and executes a small buy + sell round-trip to detect sell-tax manipulation, blacklist traps, max-wallet traps, and transfer-blocking conditions that only manifest at runtime.
3. **Reputation & Context Check** — Cross-references the contract address against public registries (deployer age, contract age, holder concentration, liquidity lock status) to surface contextual risk.

The output is a normalized **risk score from 0 to 100**, a list of triggered red flags with severity tags, and a clear verdict: `SAFE`, `CAUTION`, `HIGH RISK`, or `HONEYPOT LIKELY`.

## Primary Network

- **Pharos Mainnet** (default)

## Additional Network

- **Pharos Testnet** (Atlantic) — for testing only, no real value at risk

## When To Use

- Before swapping, staking, or LP-ing into any contract
- Before approving token allowances for an unknown contract
- When a user asks an agent "is this token safe?" or "is this a honeypot?"
- During agent-driven portfolio management on Pharos

## Functions Exposed

- `analyzeContract(address)` — Full analysis, returns risk score + verdict + findings
- `quickCheck(address)` — Fast static-only check, no fork simulation
- `simulateTrade(address, amountIn)` — Buy/sell simulation on a forked node
- `checkOwnership(address)` — Owner privilege concentration report
- `checkLiquidityLock(address)` — Liquidity lock status of the paired token

## Output Format

```json
{
  "address": "0x...",
  "network": "Pharos Mainnet",
  "riskScore": 78,
  "verdict": "HIGH RISK",
  "findings": [
    {"type": "HIDDEN_MINT", "severity": "high", "detail": "Owner can mint unlimited tokens"},
    {"type": "SELL_TAX", "severity": "high", "detail": "Sell tax simulated at 92%"}
  ],
  "recommendation": "Do not interact"
}
```

## Usage

Install the skill into an agent environment, then invoke the exposed functions through natural language. The agent will load this `SKILL.md`, identify the relevant function, and execute the appropriate script.

Example agent prompt:
> "Analyze the contract at 0xABC...123 on Pharos mainnet and tell me if it's safe to swap into."

The agent will:
1. Read this SKILL.md to understand the available functions
2. Call `analyzeContract("0xABC...123")` with the Pharos mainnet RPC
3. Return the JSON risk report to the user in plain language

## Supported Frameworks

- OpenClaw
- Claude Code
- Codex
- Any agent runtime that follows the SKILL.md convention

## Dependencies

- Node.js >= 18
- ethers.js v6
- Anvil (Foundry) for forked-chain simulation
- Optional: Pharos RPC endpoint (mainnet and/or testnet)

## Configuration

Set the following environment variables before use:

| Variable | Required | Description |
|----------|----------|-------------|
| `PHAROS_MAINNET_RPC` | Yes | HTTPS RPC URL for Pharos mainnet |
| `PHAROS_TESTNET_RPC` | No | HTTPS RPC URL for Pharos testnet (Atlantic) |
| `HPD_FORK_MODE` | No | `auto`, `always`, or `off` (default `auto`) |

## Security Notes

- Honeypot Detector is read-only by default. It never submits transactions or approves allowances.
- Forked simulations run inside an ephemeral local Anvil instance; nothing is broadcast to the live network.
- This skill provides analysis, not financial advice. Final decisions remain with the operator.
