import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { safeFetch, extractTitle, requestOnce } from './fetcher.ts';



test('safeFetch refuses non-http(s) schemes', async () => {
  const r = await safeFetch('file:///etc/passwd');
  assert.equal(r.ok, false);
  assert.equal(r.blocked?.category, 'protocol');
});

test('safeFetch refuses loopback, metadata and IPv6 loopback targets', async () => {
  for (const u of ['http://127.0.0.1/', 'http://169.254.169.254/latest/meta-data/', 'http://[::1]/']) {
    const r = await safeFetch(u);
    assert.equal(r.ok, false, `${u} must be blocked`);
    assert.ok(r.blocked, `${u} should report a block reason`);
  }
});

test('safeFetch rejects an invalid URL', async () => {
  const r = await safeFetch('not a url');
  assert.equal(r.ok, false);
  assert.equal(r.error, 'invalid URL');
});



test('extractTitle pulls and collapses the <title>', () => {
  assert.equal(extractTitle('<html><head><title>  Hello\n World </title>'), 'Hello World');
  assert.equal(extractTitle('<html>no title</html>'), undefined);
});





let server: http.Server;
let port = 0;
const optsBase = {
  maxRedirects: 8,
  timeoutMs: 5000,
  maxBytes: 1024,
  userAgent: 'test',
};

before(async () => {
  server = http.createServer((req, res) => {
    if (req.url === '/redirect') {
      res.writeHead(302, { location: '/dest' });
      res.end();
    } else if (req.url === '/big') {
      res.writeHead(200, { 'content-type': 'application/octet-stream' });
      res.end(Buffer.alloc(10_000, 0x41));
    } else {
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end('<title>Local</title><body>ok</body>');
    }
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  port = (server.address() as import('node:net').AddressInfo).port;
});

after(async () => {
  await new Promise<void>((r) => server.close(() => r()));
});

test('requestOnce reads a body and captures headers', async () => {
  const hop = await requestOnce(new URL(`http://127.0.0.1:${port}/`), '127.0.0.1', 4, optsBase);
  assert.equal(hop.status, 200);
  assert.match(hop.body.toString(), /<title>Local<\/title>/);
});

test('requestOnce surfaces redirect status + Location', async () => {
  const hop = await requestOnce(new URL(`http://127.0.0.1:${port}/redirect`), '127.0.0.1', 4, optsBase);
  assert.equal(hop.status, 302);
  assert.equal(hop.location, '/dest');
});

test('requestOnce enforces the byte cap (no unbounded download)', async () => {
  const hop = await requestOnce(new URL(`http://127.0.0.1:${port}/big`), '127.0.0.1', 4, optsBase);
  assert.equal(hop.truncated, true);
  assert.ok(hop.body.length <= optsBase.maxBytes, `body ${hop.body.length} must be capped at ${optsBase.maxBytes}`);
});
