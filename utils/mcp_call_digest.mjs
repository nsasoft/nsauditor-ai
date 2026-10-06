// utils/mcp_call_digest.mjs
// What binds an MCP tool response to its call_id (1.3.0 (s6)). The server logs a digest of the response BODY — the text
// the receipt footer is appended to — and `nsauditor-ai mcp verify-call <id> --response <file>` recomputes it from the
// text the user saved. The digest is never printed: a printed digest would replay together with the id.
//
// Canonicalisation is WHITESPACE-INSENSITIVE and WORD-EXACT (ruled): every whitespace run, newlines included, becomes
// one space and the ends are trimmed. A copy that a client soft-wrapped or re-flowed still verifies; a changed word
// does not. Stated limits: a RENDERED copy (Markdown turned into bullets and bold) is a different text and refutes —
// copy the raw tool output; and differences inside code blocks that are whitespace only (indentation) are not seen.

import { createHash } from 'node:crypto';

/** The first line of the footer every tool response carries. */
export const RECEIPT_MARKER = '── MCP call receipt ──';

/** The response reduced to its words: every whitespace run becomes one space, the ends trimmed. */
export function canonicalResponse(text) {
  return String(text ?? '').replace(/\s+/g, ' ').trim();
}

/** SHA-256 (hex) of the canonical response body. */
export function responseDigest(body) {
  return createHash('sha256').update(canonicalResponse(body), 'utf8').digest('hex');
}

/** The body of a saved response: everything before the receipt footer, which is not part of what the tool produced. */
export function bodyOf(saved) {
  const text = String(saved ?? '');
  const at = text.lastIndexOf(RECEIPT_MARKER);
  return at < 0 ? text : text.slice(0, at);
}
