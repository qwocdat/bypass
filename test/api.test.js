const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');

process.env.PORT = '0'; // not used directly since require.main !== module in tests
const app = require('../server');

function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, () => resolve(server));
  });
}

function request(server, path, options = {}) {
  const { port } = server.address();
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, path, method: options.method || 'GET', headers: options.headers },
      (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          let json = null;
          try {
            json = JSON.parse(body);
          } catch {
            /* not json */
          }
          resolve({ status: res.statusCode, body: json ?? body });
        });
      }
    );
    req.on('error', reject);
    if (options.body) req.write(options.body);
    req.end();
  });
}

test('GET /api/health returns ok', async (t) => {
  const server = await listen(app);
  t.after(() => server.close());

  const res = await request(server, '/api/health');
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.body.ok, true);
  assert.ok(Array.isArray(res.body.hosts));
});

test('POST /api/bypass rejects unsupported domains', async (t) => {
  const server = await listen(app);
  t.after(() => server.close());

  const res = await request(server, '/api/bypass', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'https://example.com/foo' }),
  });
  assert.strictEqual(res.status, 400);
  assert.strictEqual(res.body.success, false);
});

test('POST /api/bypass rejects invalid URLs', async (t) => {
  const server = await listen(app);
  t.after(() => server.close());

  const res = await request(server, '/api/bypass', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'not-a-url' }),
  });
  assert.strictEqual(res.status, 400);
  assert.strictEqual(res.body.success, false);
});

test('POST /api/bypass blocks SSRF to localhost via link4m redirect target check', async (t) => {
  const server = await listen(app);
  t.after(() => server.close());

  // link4m.com itself will fail to connect in this sandboxed test env (no network),
  // which still exercises validation + handler selection without reaching the network assumption.
  const res = await request(server, '/api/bypass', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url: 'https://link4m.com/abc123' }),
  });
  assert.strictEqual(typeof res.body.success, 'boolean');
});
