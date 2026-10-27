import { test } from 'node:test';
import assert from 'node:assert/strict';
import { RECEIPT_MARKER, bodyOf, responseDigest } from '../utils/mcp_call_digest.mjs';

// `verify-call` is whitespace-insensitive by ruling — a soft-wrapped or re-flowed copy of the raw output verifies — but
// `bodyOf()` found the receipt footer with an EXACT `lastIndexOf(RECEIPT_MARKER)`. The marker carries spaces
// (`── MCP call receipt ──`), so a copy whose wrap fell inside it lost its footer: the digest then covered body AND
// footer and the copy was REFUTED. Found 2026-10-27 when a change of denial wording moved the marker under the soft-wrap
// leg in tests/mcp_verify_call_binding.test.mjs (that leg wraps every space at an index divisible by 37). The marker is
// now found whitespace-insensitively, and the LAST one still wins.
// FOURTH QUADRANT FIRST: a copy with the marker intact is cut exactly where it always was.

const BODY = 'scan_host found 3 open ports.\n\n**Tools available to you now:** scan_host, list_plugins';
const FOOTER = `\n\n${RECEIPT_MARKER}\ncall_id: 9a1b2c3d-4e5f-4a6b-8c7d-0e1f2a3b4c5d`;

test('(first) the marker intact: the body is everything before it', () => {
  assert.equal(bodyOf(BODY + FOOTER), `${BODY}\n\n`);
});

test('a copy wrapped INSIDE the marker still has its footer cut, so its body digest matches the original', () => {
  const wrappedMarker = RECEIPT_MARKER.replace(/ /g, '\r\n  ');
  assert.notEqual(wrappedMarker, RECEIPT_MARKER, 'positive control: the marker itself was wrapped');
  const copy = BODY.replace(/ /g, '\n') + FOOTER.replace(RECEIPT_MARKER, wrappedMarker);
  assert.equal(responseDigest(bodyOf(copy)), responseDigest(bodyOf(BODY + FOOTER)));
});

test('a body that itself quotes the marker is still cut at the LAST marker, wrapped or not', () => {
  const quoting = `${BODY}\nthe footer reads "${RECEIPT_MARKER}" in every response`;
  const original = quoting + FOOTER;
  const copy = quoting.replace(/ /g, '\n  ') + FOOTER.replace(RECEIPT_MARKER, RECEIPT_MARKER.replace(/ /g, '\n'));
  assert.equal(responseDigest(bodyOf(copy)), responseDigest(bodyOf(original)));
  assert.ok(bodyOf(original).includes(`"${RECEIPT_MARKER}"`), 'the quoted marker in the body was cut as the footer');
});

test('a changed WORD in the marker is not a marker: nothing is cut', () => {
  const tampered = BODY + FOOTER.replace('receipt', 'receipts');
  assert.equal(bodyOf(tampered), tampered);
});
