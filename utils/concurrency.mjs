// utils/concurrency.mjs
//
// Minimal bounded-concurrency runner: run fn(item, index) over items with at
// most `limit` in flight, returning results in input order. A thrown fn rejects
// the whole call — callers that need per-item isolation should catch inside fn.

export async function mapLimit(items, limit, fn) {
  const list = Array.isArray(items) ? items : [];
  const n = list.length;
  const out = new Array(n);
  const cap = Math.max(1, Math.min((limit | 0) || 1, n || 1));
  let next = 0;
  async function worker() {
    while (next < n) {
      const i = next++;
      out[i] = await fn(list[i], i);
    }
  }
  await Promise.all(Array.from({ length: Math.min(cap, n) }, () => worker()));
  return out;
}
