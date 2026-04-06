import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';

import { sendWebhook, buildAlertPayload } from '../utils/webhook.mjs';

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

/**
 * Create a temporary HTTP server for integration tests.
 * Returns { url, server, close(), requests[] }.
 */
function createTestServer(handler) {
  return new Promise((resolve, reject) => {
    const requests = [];
    const server = http.createServer((req, res) => {
      const chunks = [];
      req.on('data', (c) => chunks.push(c));
      req.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf8');
        requests.push({ method: req.method, url: req.url, headers: req.headers, body });
        handler(req, res, body);
      });
    });
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      const url = `http://127.0.0.1:${port}`;
      resolve({
        url,
        server,
        requests,
        close: () => new Promise((r) => server.close(r)),
      });
    });
    server.on('error', reject);
  });
}

// ---------------------------------------------------------------------------
// buildAlertPayload
// ---------------------------------------------------------------------------

test('buildAlertPayload produces correct structure', () => {
  const findings = [
    { port: 22, protocol: 'tcp', service: 'ssh', description: 'Weak key exchange' },
    { port: 80, protocol: 'tcp', service: 'http', severity: 'medium', summary: 'HTTP exposed' },
  ];
  const payload = buildAlertPayload('10.0.0.1', findings, 'high');

  assert.equal(payload.host, '10.0.0.1');
  assert.equal(payload.severity, 'high');
  assert.equal(payload.findingsCount, 2);
  assert.ok(payload.timestamp);
  assert.ok(payload.summary.includes('2 finding(s)'));
  assert.equal(payload.details.length, 2);
  assert.equal(payload.details[0].port, 22);
  assert.equal(payload.details[0].description, 'Weak key exchange');
  assert.equal(payload.details[1].description, 'HTTP exposed');
});

test('buildAlertPayload handles empty findings', () => {
  const payload = buildAlertPayload('10.0.0.1', []);
  assert.equal(payload.findingsCount, 0);
  assert.equal(payload.details.length, 0);
  assert.equal(payload.severity, 'high'); // default
});

test('buildAlertPayload handles non-array findings', () => {
  const payload = buildAlertPayload('10.0.0.1', null, 'critical');
  assert.equal(payload.findingsCount, 0);
  assert.equal(payload.severity, 'critical');
  assert.deepEqual(payload.details, []);
});

// ---------------------------------------------------------------------------
// sendWebhook — URL validation
// ---------------------------------------------------------------------------

test('sendWebhook rejects invalid URLs', async () => {
  const result = await sendWebhook('ftp://bad.example.com', { data: 1 });
  assert.equal(result.success, false);
  assert.ok(result.error.includes('Invalid URL'));
});

test('sendWebhook rejects non-URL strings', async () => {
  const result = await sendWebhook('not-a-url', { data: 1 });
  assert.equal(result.success, false);
  assert.ok(result.error.includes('Invalid URL'));
});

// ---------------------------------------------------------------------------
// sendWebhook — integration with local server
// ---------------------------------------------------------------------------

test('sendWebhook sends POST with JSON body', async () => {
  const ts = await createTestServer((req, res) => {
    res.writeHead(200);
    res.end('ok');
  });

  try {
    const payload = { alert: true, host: '10.0.0.1' };
    const result = await sendWebhook(ts.url + '/hook', payload, { retries: 0 });

    assert.equal(result.success, true);
    assert.equal(result.statusCode, 200);
    assert.equal(ts.requests.length, 1);
    assert.equal(ts.requests[0].method, 'POST');
    assert.deepEqual(JSON.parse(ts.requests[0].body), payload);
    assert.equal(ts.requests[0].headers['content-type'], 'application/json');
  } finally {
    await ts.close();
  }
});

test('sendWebhook retries on failure then succeeds', async () => {
  let callCount = 0;
  const ts = await createTestServer((req, res) => {
    callCount++;
    if (callCount < 3) {
      res.writeHead(500);
      res.end('fail');
    } else {
      res.writeHead(200);
      res.end('ok');
    }
  });

  try {
    const result = await sendWebhook(ts.url, { data: 1 }, {
      retries: 2,
      retryDelayMs: 10, // fast retries for tests
    });
    assert.equal(result.success, true);
    assert.equal(callCount, 3);
  } finally {
    await ts.close();
  }
});

test('sendWebhook returns failure after all retries exhausted', async () => {
  const ts = await createTestServer((req, res) => {
    res.writeHead(503);
    res.end('unavailable');
  });

  try {
    const result = await sendWebhook(ts.url, { data: 1 }, {
      retries: 1,
      retryDelayMs: 10,
    });
    assert.equal(result.success, false);
    assert.equal(result.statusCode, 503);
  } finally {
    await ts.close();
  }
});

test('sendWebhook handles connection errors', async () => {
  // Use a port that nothing is listening on
  const result = await sendWebhook('http://127.0.0.1:1', { data: 1 }, {
    retries: 0,
    timeout: 500,
  });
  assert.equal(result.success, false);
  assert.equal(result.statusCode, 0);
  assert.ok(result.error);
});
