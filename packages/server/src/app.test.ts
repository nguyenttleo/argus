import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { buildApp } from './app.ts';
import { loadServerConfig } from './config.ts';
import { ArgusDb } from './db.ts';
import type { FastifyInstance } from 'fastify';

const EICAR = Buffer.from(
  'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=',
  'base64',
);

const config = {
  ...loadServerConfig({ ARGUS_DATA_DIR: '.data-test' }),
  // keep tests offline + fast
  urlFetchDefault: false,
  reputationDefault: true,
  rateLimitMax: 1000,
};

let app: FastifyInstance;
let db: ArgusDb;

before(async () => {
  db = new ArgusDb(':memory:');
  app = await buildApp(config, { db, quarantine: null });
});
after(async () => {
  await app.close();
  db.close();
});

function multipartBody(filename: string, content: Buffer): { payload: Buffer; headers: Record<string, string> } {
  const boundary = '----argustest' + Math.random().toString(16).slice(2);
  const head = Buffer.from(
    `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`,
  );
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`);
  return {
    payload: Buffer.concat([head, content, tail]),
    headers: { 'content-type': `multipart/form-data; boundary=${boundary}` },
  };
}

test('GET /api/health reports status + rule count', async () => {
  const res = await app.inject({ method: 'GET', url: '/api/health' });
  assert.equal(res.statusCode, 200);
  const body = res.json();
  assert.equal(body.status, 'ok');
  assert.ok(body.rulesLoaded >= 7);
});

test('POST /api/scan/url scores a phishing URL malicious and persists it', async () => {
  const res = await app.inject({
    method: 'POST',
    url: '/api/scan/url',
    payload: { url: 'http://paypal.com@secure-paypa1-login.tk/webscr?cmd=verify' },
  });
  assert.equal(res.statusCode, 200);
  const report = res.json();
  assert.equal(report.verdict, 'malicious');
  assert.equal(report.kind, 'url');

  // persisted + retrievable
  const get = await app.inject({ method: 'GET', url: `/api/scan/${report.id}` });
  assert.equal(get.statusCode, 200);
  assert.equal(get.json().id, report.id);
});

test('POST /api/scan/url benign popular URL is safe', async () => {
  const res = await app.inject({ method: 'POST', url: '/api/scan/url', payload: { url: 'https://www.google.com/' } });
  assert.equal(res.json().verdict, 'safe');
});

test('POST /api/scan/url rejects missing / invalid URL', async () => {
  assert.equal((await app.inject({ method: 'POST', url: '/api/scan/url', payload: {} })).statusCode, 400);
  const bad = await app.inject({ method: 'POST', url: '/api/scan/url', payload: { url: 'http://' } });
  assert.equal(bad.statusCode, 400);
  assert.equal(bad.json().error, 'invalid_url');
});

test('POST /api/scan/file detects EICAR as malicious', async () => {
  const mp = multipartBody('eicar.com', EICAR);
  const res = await app.inject({ method: 'POST', url: '/api/scan/file', payload: mp.payload, headers: mp.headers });
  assert.equal(res.statusCode, 200);
  const report = res.json();
  assert.equal(report.verdict, 'malicious');
  assert.equal(report.detail.sha256, '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');
});

test('POST /api/scan/file with no file → 400', async () => {
  const res = await app.inject({
    method: 'POST',
    url: '/api/scan/file',
    payload: Buffer.from('not multipart'),
    headers: { 'content-type': 'multipart/form-data; boundary=zzz' },
  });
  assert.equal(res.statusCode, 400);
});

test('GET /api/scans lists history; /api/stats aggregates', async () => {
  const list = await app.inject({ method: 'GET', url: '/api/scans?limit=10' });
  assert.equal(list.statusCode, 200);
  assert.ok(Array.isArray(list.json().scans));
  assert.ok(list.json().scans.length >= 2);

  const stats = await app.inject({ method: 'GET', url: '/api/stats' });
  const s = stats.json();
  assert.ok(s.total >= 2);
  assert.ok(s.byVerdict.malicious >= 1);
});

test('GET /api/scan/:id 404s for unknown id', async () => {
  const res = await app.inject({ method: 'GET', url: '/api/scan/does-not-exist' });
  assert.equal(res.statusCode, 404);
});

test('IOC search finds a scan by extracted indicator', async () => {
  // scan a file containing a known URL IOC, then search for it
  const mp = multipartBody('c2.txt', Buffer.from('beacon http://evil.example.org/gate.php'));
  await app.inject({ method: 'POST', url: '/api/scan/file', payload: mp.payload, headers: mp.headers });
  const res = await app.inject({ method: 'GET', url: '/api/iocs/' + encodeURIComponent('http://evil.example.org/gate.php') });
  assert.equal(res.statusCode, 200);
  assert.ok(res.json().scans.length >= 1);
});

test('repeat scans hit the cache (same report); fresh:true bypasses it', async () => {
  const body = { url: 'https://example.org/cache-test' };
  const first = (await app.inject({ method: 'POST', url: '/api/scan/url', payload: body })).json();
  const second = (await app.inject({ method: 'POST', url: '/api/scan/url', payload: body })).json();
  assert.equal(second.id, first.id, 'identical request should return the cached report');

  const fresh = (await app.inject({ method: 'POST', url: '/api/scan/url', payload: { ...body, fresh: true } })).json();
  assert.notEqual(fresh.id, first.id, 'fresh:true should re-analyze');
});

test('dashboard metadata endpoints are not counted by the scan rate limiter', async () => {
  const limitedDb = new ArgusDb(':memory:');
  const limitedApp = await buildApp({ ...config, rateLimitMax: 1 }, { db: limitedDb, quarantine: null });
  try {
    assert.equal((await limitedApp.inject({ method: 'GET', url: '/api/health' })).statusCode, 200);
    assert.equal((await limitedApp.inject({ method: 'GET', url: '/api/health' })).statusCode, 200);
    assert.equal((await limitedApp.inject({ method: 'GET', url: '/api/stats' })).statusCode, 200);
    assert.equal((await limitedApp.inject({ method: 'GET', url: '/api/stats' })).statusCode, 200);

    assert.equal(
      (await limitedApp.inject({ method: 'POST', url: '/api/scan/url', payload: { url: 'https://example.com/' } })).statusCode,
      200,
    );
    assert.equal(
      (await limitedApp.inject({ method: 'POST', url: '/api/scan/url', payload: { url: 'https://example.org/' } })).statusCode,
      429,
    );
  } finally {
    await limitedApp.close();
    limitedDb.close();
  }
});
