// utils/redact.mjs
// Replace values whose KEY contains any of the given keywords.
// Example: scrubByKey({ serialNumber: 'X8K...' }, ['serial']) -> { serialNumber: '[REDACTED_HIDDEN]' }

export function scrubByKey(val, keywords, placeholder = '[REDACTED_HIDDEN]') {
  if (val == null) return val;

  if (Array.isArray(val)) {
    return val.map(v => scrubByKey(v, keywords, placeholder));
  }

  if (typeof val === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(val)) {
      const lk = k.toLowerCase();
      const hit = keywords.some(word => lk.includes(word));
      out[k] = hit ? placeholder : scrubByKey(v, keywords, placeholder);
    }
    return out;
  }

  return val; // primitives pass through
}

// Pattern-based redaction rules
const PATTERNS = [
  // Standard level
  { regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, replacement: '[REDACTED_EMAIL]', level: 'standard' },
  { regex: /\b[\w-]+\.(internal|local|corp|lan|intra|priv)\b/gi, replacement: '[REDACTED_HOSTNAME]', level: 'standard' },
  { regex: /https?:\/\/(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\S+/g, replacement: '[REDACTED_URL]', level: 'standard' },
  { regex: /community=\S+/gi, replacement: 'community=[REDACTED]', level: 'standard' },
  { regex: /\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b/gi, replacement: '[REDACTED_MAC]', level: 'standard' },
  // Strict level
  { regex: /(?:\/[\w.-]+){2,}\.(?:conf|log|ini|cfg|env|key|pem|crt)\b/g, replacement: '[REDACTED_PATH]', level: 'strict' },
  { regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, replacement: '[REDACTED_AWS_KEY]', level: 'strict' },
  { regex: /\bBearer\s+[A-Za-z0-9._~+\/=-]+/gi, replacement: '[REDACTED_BEARER]', level: 'strict' },
];

/**
 * Redact sensitive patterns from string values within an object tree.
 * Applies regex-based redaction to all string values recursively.
 * @param {*} val - Value to redact
 * @param {string} level - 'standard' or 'strict'
 * @returns {*} Redacted value
 */
export function redactPatterns(val, level = 'standard') {
  const activePatterns = PATTERNS.filter(
    p => p.level === 'standard' || (level === 'strict' && p.level === 'strict')
  );
  return _applyPatterns(val, activePatterns);
}

function _applyPatterns(val, patterns) {
  if (val == null) return val;

  if (typeof val === 'string') {
    let result = val;
    for (const { regex, replacement } of patterns) {
      // Reset lastIndex for global regexes
      regex.lastIndex = 0;
      result = result.replace(regex, replacement);
    }
    return result;
  }

  if (Array.isArray(val)) {
    return val.map(v => _applyPatterns(v, patterns));
  }

  if (typeof val === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(val)) {
      out[k] = _applyPatterns(v, patterns);
    }
    return out;
  }

  return val;
}
