# Honeypot Detector (HPD)

A professional smart contract security analysis skill. HPD combines static analysis, behavioral simulation, and onchain reputation checks to detect honeypots, rug pulls, hidden mints, owner-only withdrawals, and other malicious patterns on EVM smart contracts.

## Overview

Honeypot Detector evaluates any EVM smart contract and returns a normalized **risk score from 0 to 100** with a clear verdict:

- `SAFE` — no major red flags
- `CAUTION` — minor risks detected
- `HIGH RISK` — strong indicators of malicious behavior
- `HONEYPOT LIKELY` — almost certainly a scam

The skill is designed to be invoked by AI agents before they interact with an unknown contract, but it can also be used directly from the command line.

## Features

- **Static analysis** — scans deployed bytecode for 30+ known-dangerous function selectors (hidden mint, blacklist, pause, owner withdraw, fee manipulation, proxy upgrade, selfdestruct).
- **Behavioral simulation** — forks the target chain locally, deploys a copy of the contract, and runs a small buy + sell round-trip to surface runtime traps.
- **Reputation & context** — inspects contract age, deployer, holder concentration, and liquidity lock status.
- **Risk scoring** — combines all findings into a single 0-100 score and a plain-language verdict.
- **Structured output** — returns a clean JSON report that an agent can narrate to the user.

## Network

| Network | Role | Chain ID |
|---------|------|----------|
| **Pharos Mainnet** | Primary | 1672 |
| Pharos Testnet (Atlantic) | Additional, for testing | 688689 |

The default network is Pharos Mainnet. Pass `--network=pharos-testnet` to analyze a contract on the Atlantic testnet.

## Framework

- **Node.js** >= 18
- **ethers.js** v6
- **Anvil** (Foundry) for forked-chain behavioral simulation

## Installation

```bash
git clone https://github.com/ademidun69/HPD.git
cd HPD
npm install
```

## Configuration

HPD reads the Pharos RPC URL from one of these places, in order:

1. The `--rpc=<url>` CLI flag (per-invocation override)
2. The `PHAROS_MAINNET_RPC` environment variable (recommended for daily use)
3. The `~/.hpd/config.json` file written by `hpd init` (optional)

| Variable | Required | Description |
|----------|----------|-------------|
| `PHAROS_MAINNET_RPC` | Recommended | HTTPS RPC URL for Pharos mainnet |
| `PHAROS_TESTNET_RPC` | No | HTTPS RPC URL for Pharos testnet (Atlantic) |
| `HPD_FORK_MODE` | No | `auto`, `always`, or `off` (default `auto`) |

**Quickest setup** (one line, no init step):

```bash
export PHAROS_MAINNET_RPC="https://rpc.pharos.xyz"
```

**Optional persistence** (saved to `~/.hpd/config.json`):

```bash
hpd init
```

> ⚠️ **`hpd init` only prompts when run from a real terminal** (TTY). If you run it from a pasted code block in Termux, it will print the env-var command above instead of prompting — that is intentional, because pasted blocks feed every line to the next prompt and produce garbage input.

## Usage

### As a Library

```javascript
const hpd = require("./src/index");

(async () => {
  const report = await hpd.analyzeContract("0xYourContractAddress", {
    network: "pharos-mainnet",  // or "pharos-testnet"
  });

  console.log(report.riskScore, report.verdict);
  console.log(report.findings);
})();
```

### Programmatic Functions

- `analyzeContract(address, options)` — full analysis
- `quickCheck(address, options)` — static-only
- `simulateTrade(address, amountIn, options)` — buy/sell simulation
- `checkOwnership(address, options)` — owner privileges
- `checkLiquidityLock(address, options)` — liquidity lock status

### Output Format

```json
{
  "address": "0x...",
  "network": "Pharos Mainnet",
  "riskScore": 78,
  "verdict": "HIGH RISK",
  "findings": [
    { "type": "HIDDEN_MINT", "severity": "high", "detail": "..." }
  ],
  "recommendation": "Avoid. Strong indicators of malicious behavior."
}
```

### Command Line

The skill ships with a full-featured CLI. Two ways to use it:

#### Option A: Use the wrapper script (no global install)

The wrapper script lives at `./hpd` after `git clone`. It does not require `npm install -g` and works from any clone.

```bash
# After git clone + npm install:
./hpd --version
PHAROS_MAINNET_RPC="https://rpc.pharos.xyz" ./hpd quick 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
```

#### Option B: Install globally with npm

```bash
git clone https://github.com/ademidun69/HPD.git
cd HPD
npm install -g .
hpd --version
```

#### All commands

```bash
hpd analyze <address> [options]    # Full analysis (static + sim + reputation)
hpd quick <address> [options]      # Static-only check (no fork simulation)
hpd simulate <address> <amount>    # Buy/sell simulation on a forked node
hpd ownership <address> [options]  # Owner privilege report
hpd liquidity <address> [options]  # Liquidity lock status
hpd watch <address> [options]      # Live monitoring (re-analyze on interval)
hpd init                            # Optional: save RPC URL to ~/.hpd/config.json
hpd demo                            # Open the interactive demo page
hpd version                         # Show version
hpd help                            # Show full help
```

#### All options

| Option | Description |
|--------|-------------|
| `--network=pharos-mainnet` | Use Pharos mainnet (default) |
| `--network=pharos-testnet` | Use Pharos Atlantic testnet |
| `--no-sim` | Skip the forked-chain simulation (faster) |
| `--json` | Output raw JSON instead of formatted report |
| `--no-color` | Disable colored output |
| `--rpc=<url>` | Override the RPC URL for this invocation |
| `--interval=<seconds>` | Watch interval in seconds (default 30) |

#### Examples

```bash
# Full analysis on mainnet (RPC from env var)
PHAROS_MAINNET_RPC="https://rpc.pharos.xyz" hpd analyze 0xdAC17F958D2ee523a2206206994597C13D831ec7

# Override RPC inline
hpd quick 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 --rpc=https://rpc.pharos.xyz

# Static-only check, no colors
hpd quick 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 --no-sim --no-color

# Output as JSON for piping into other tools
hpd quick 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 --no-sim --json | jq .riskScore

# Bare-address shorthand
hpd 0xdAC17F958D2ee523a2206206994597C13D831ec7

# Watch a contract in real time
hpd watch 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 --interval=60

# Use the testnet
hpd analyze 0xYourTestnetAddress --network=pharos-testnet
```

#### Direct invocation (no wrapper)

If you don't want to use the wrapper, you can always call node directly:

```bash
PHAROS_MAINNET_RPC="https://rpc.pharos.xyz" node src/cli.js analyze 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
```

## Tests

```bash
npm test
```

Tests cover selector extraction, risk aggregation, verdict thresholds, and recommendation logic. They run offline without requiring an RPC.

## Project Structure

```
.
├── SKILL.md                 # Skill definition for AI agents
├── README.md
├── package.json
├── hpd                       # Bash wrapper script
├── src/
│   ├── index.js             # Public API
│   ├── cli.js               # Command-line interface
│   ├── static-analysis.js   # Bytecode + selector inspection
│   ├── simulator.js         # Forked-chain buy/sell simulation
│   ├── reputation.js        # Onchain context (age, deployer, holders)
│   └── scorer.js            # Risk aggregation + verdict logic
└── test/
    └── run.test.js          # Offline unit tests
```

## Security Notes

- Honeypot Detector is read-only by default. It never submits transactions or approves allowances on the live network.
- Forked simulations run inside an ephemeral local Anvil instance; nothing is broadcast.
- This skill provides analysis, not financial advice. Final decisions remain with the operator.

## Dependencies

- `ethers` ^6.13.0
- `chalk` ^4.1.2

## License

MIT
