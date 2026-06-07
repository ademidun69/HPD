/**
 * Risk scorer.
 * Aggregates findings into a 0-100 risk score and a verdict.
 */

const SEVERITY_WEIGHTS = {
  critical: 80,
  high: 35,
  medium: 15,
  low: 3,
};

const VERDICT_THRESHOLDS = {
  HONEYPOT_LIKELY: 60,
  HIGH_RISK: 30,
  CAUTION: 10,
  SAFE: 0,
};

function aggregate(findings) {
  let score = 0;
  for (const f of findings) {
    const w = SEVERITY_WEIGHTS[f.severity] || 0;
    score += w;
  }
  if (score > 100) score = 100;

  let verdict = "SAFE";
  if (score >= VERDICT_THRESHOLDS.HONEYPOT_LIKELY) verdict = "HONEYPOT LIKELY";
  else if (score >= VERDICT_THRESHOLDS.HIGH_RISK) verdict = "HIGH RISK";
  else if (score >= VERDICT_THRESHOLDS.CAUTION) verdict = "CAUTION";

  return { score, verdict };
}

function recommend(verdict) {
  switch (verdict) {
    case "HONEYPOT LIKELY": return "Do not interact. Treat as a scam.";
    case "HIGH RISK": return "Avoid. Strong indicators of malicious behavior.";
    case "CAUTION": return "Proceed only with full understanding of the listed risks.";
    case "SAFE":
    default:
      return "No major red flags detected. Standard caution still advised.";
  }
}

module.exports = { aggregate, recommend, SEVERITY_WEIGHTS, VERDICT_THRESHOLDS };
