/**
 * Reputation and context check.
 * Pulls onchain context: deployer age, contract age, holder concentration, etc.
 */

const { ethers } = require("ethers");

async function run(address, provider) {
  const findings = [];
  const summary = { contractAge: null, deployer: null, holderCount: 0, topHolderPct: 0 };

  try {
    const code = await provider.getCode(address);
    if (code === "0x" || code === "0x0") {
      return { findings, summary };
    }

    const head = await provider.getBlockNumber();
    const deployBlock = await findCreationBlock(address, provider, head);

    if (deployBlock !== null) {
      const block = await provider.getBlock(deployBlock);
      summary.contractAge = Math.floor((Date.now() / 1000) - block.timestamp);
      summary.deployBlock = deployBlock;
      summary.deployTimestamp = block.timestamp;

      if (summary.contractAge < 3600) {
        findings.push({
          type: "NEW_CONTRACT",
          severity: "high",
          detail: `Contract was deployed less than 1 hour ago (${summary.contractAge}s).`,
        });
      } else if (summary.contractAge < 86400) {
        findings.push({
          type: "YOUNG_CONTRACT",
          severity: "medium",
          detail: `Contract was deployed less than 24 hours ago.`,
        });
      }

      const tx = block.transactions && block.transactions[0];
      if (tx) {
        const txReceipt = await provider.getTransaction(tx);
        summary.deployer = txReceipt.from;
      }
    }
  } catch (err) {
    findings.push({
      type: "REPUTATION_READ_ERROR",
      severity: "low",
      detail: `Could not read reputation data: ${err.message}`,
    });
  }

  return { findings, summary };
}

async function ownership(address, provider) {
  const summary = { owner: null, ownerCanMint: false, ownerCanPause: false, ownerCanBlacklist: false };
  const findings = [];

  try {
    const rawOwner = await provider.getStorage(address, 0);
    if (rawOwner && rawOwner !== "0x0000000000000000000000000000000000000000000000000000000000000000") {
      const owner = "0x" + rawOwner.slice(26);
      summary.owner = ethers.getAddress(owner);
    }
  } catch (_) {}

  return { summary, findings };
}

async function liquidityLock(address, provider) {
  const findings = [];
  const summary = { locked: null, lockContract: null, lockExpiry: null };

  findings.push({
    type: "LIQUIDITY_LOCK_UNKNOWN",
    severity: "low",
    detail: "Liquidity lock status could not be verified without an explorer or registry endpoint.",
  });

  return { summary, findings };
}

async function findCreationBlock(address, provider, head, lookback = 50000) {
  const fromBlock = Math.max(0, head - lookback);
  try {
    const logs = await provider.getLogs({
      fromBlock,
      toBlock: head,
      address,
    });
    if (logs.length > 0) {
      return logs[0].blockNumber;
    }
  } catch (_) {}
  return null;
}

module.exports = { run, ownership, liquidityLock };
