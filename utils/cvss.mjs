// utils/cvss.mjs
// CVSS v3.1 base score calculator following the FIRST.org specification.
// Pure implementation — no external dependencies.

const METRIC_WEIGHTS = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.20 },
  AC: { L: 0.77, H: 0.44 },
  PR: {
    U: { N: 0.85, L: 0.62, H: 0.27 },
    C: { N: 0.85, L: 0.68, H: 0.50 },
  },
  UI: { N: 0.85, R: 0.62 },
  C:  { H: 0.56, L: 0.22, N: 0 },
  I:  { H: 0.56, L: 0.22, N: 0 },
  A:  { H: 0.56, L: 0.22, N: 0 },
};

const VALID_VALUES = {
  AV: ['N', 'A', 'L', 'P'],
  AC: ['L', 'H'],
  PR: ['N', 'L', 'H'],
  UI: ['N', 'R'],
  S:  ['U', 'C'],
  C:  ['H', 'L', 'N'],
  I:  ['H', 'L', 'N'],
  A:  ['H', 'L', 'N'],
};

const REQUIRED_METRICS = ['AV', 'AC', 'PR', 'UI', 'S', 'C', 'I', 'A'];

function roundUp(val) {
  return Math.ceil(val * 10) / 10;
}

/**
 * Parse a CVSS v3.1 vector string into a metrics object.
 * @param {string} vectorString — e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
 * @returns {{ AV: string, AC: string, PR: string, UI: string, S: string, C: string, I: string, A: string }}
 */
export function parseCvssVector(vectorString) {
  if (typeof vectorString !== 'string') {
    throw new Error('CVSS vector must be a string');
  }

  const trimmed = vectorString.trim();
  if (!trimmed.startsWith('CVSS:3.1/')) {
    throw new Error(`Invalid CVSS v3.1 vector prefix: "${trimmed}"`);
  }

  const parts = trimmed.slice('CVSS:3.1/'.length).split('/');
  const metrics = {};

  for (const part of parts) {
    const [key, value] = part.split(':');
    if (!key || value === undefined) {
      throw new Error(`Malformed metric component: "${part}"`);
    }
    if (!VALID_VALUES[key]) {
      throw new Error(`Unknown metric key: "${key}"`);
    }
    if (!VALID_VALUES[key].includes(value)) {
      throw new Error(`Invalid value "${value}" for metric "${key}". Valid: ${VALID_VALUES[key].join(', ')}`);
    }
    metrics[key] = value;
  }

  for (const req of REQUIRED_METRICS) {
    if (!metrics[req]) {
      throw new Error(`Missing required metric: "${req}"`);
    }
  }

  return metrics;
}

/**
 * Calculate the CVSS v3.1 base score from a metrics object.
 * @param {{ AV: string, AC: string, PR: string, UI: string, S: string, C: string, I: string, A: string }} metrics
 * @returns {number} Base score 0.0–10.0
 */
export function calculateBaseScore(metrics) {
  const scopeChanged = metrics.S === 'C';

  const cWeight = METRIC_WEIGHTS.C[metrics.C];
  const iWeight = METRIC_WEIGHTS.I[metrics.I];
  const aWeight = METRIC_WEIGHTS.A[metrics.A];

  const iss = 1 - ((1 - cWeight) * (1 - iWeight) * (1 - aWeight));

  let impact;
  if (scopeChanged) {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  } else {
    impact = 6.42 * iss;
  }

  if (impact <= 0) return 0.0;

  const avWeight = METRIC_WEIGHTS.AV[metrics.AV];
  const acWeight = METRIC_WEIGHTS.AC[metrics.AC];
  const prWeight = scopeChanged
    ? METRIC_WEIGHTS.PR.C[metrics.PR]
    : METRIC_WEIGHTS.PR.U[metrics.PR];
  const uiWeight = METRIC_WEIGHTS.UI[metrics.UI];

  const exploitability = 8.22 * avWeight * acWeight * prWeight * uiWeight;

  let baseScore;
  if (scopeChanged) {
    baseScore = roundUp(Math.min(1.08 * (impact + exploitability), 10));
  } else {
    baseScore = roundUp(Math.min(impact + exploitability, 10));
  }

  return baseScore;
}

/**
 * Map a numeric CVSS score to its severity label per CVSS v3.1 spec.
 * @param {number} score — 0.0–10.0
 * @returns {"None"|"Low"|"Medium"|"High"|"Critical"}
 */
export function severityFromScore(score) {
  if (score === 0.0) return 'None';
  if (score <= 3.9) return 'Low';
  if (score <= 6.9) return 'Medium';
  if (score <= 8.9) return 'High';
  return 'Critical';
}
