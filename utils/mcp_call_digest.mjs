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

/** SHA-256 (hex) of a saved request file's EXACT bytes. No canonicalisation: the server writes the file and reads it
 *  back, so the bytes are the record — a re-saved or re-formatted copy is a different file. */
export function requestDigest(bytes) {
  return createHash('sha256').update(Buffer.isBuffer(bytes) ? bytes : Buffer.from(String(bytes ?? ''), 'utf8')).digest('hex');
}

// The marker as a pattern whose whitespace is any whitespace run: the canonicalisation above is whitespace-insensitive,
// so finding the footer must be as well — the marker carries spaces, and an exact search lost the footer of a copy whose
// soft wrap fell inside it, refuting that copy (found 2026-10-27; tests/mcp_call_digest_marker_whitespace.test.mjs).
const MARKER_RE = new RegExp(RECEIPT_MARKER.trim().split(/\s+/).map((w) => w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('\\s+'), 'g');

/** The body of a saved response: everything before the LAST receipt marker (found whitespace-insensitively), which
 *  begins the footer — not part of what the tool produced. */
export function bodyOf(saved) {
  const text = String(saved ?? '');
  let at = -1;
  for (const m of text.matchAll(MARKER_RE)) at = m.index;
  return at < 0 ? text : text.slice(0, at);
}
