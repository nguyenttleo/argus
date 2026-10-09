import { test } from 'node:test';
import assert from 'node:assert/strict';
import { guardHost, isAllowedProtocol, type Resolver } from './ssrf.ts';

const fakeResolver =
  (map: Record<string, string[]>): Resolver =>
  async (host) => {
    const ips = map[host];
    if (!ips) throw new Error(`ENOTFOUND ${host}`);
    return ips.map((address) => ({ address, family: address.includes(':') ? 6 : 4 }));
  };

test('protocol allowlist is http/https only', () => {
  assert.equal(isAllowedProtocol('http:'), true);
  assert.equal(isAllowedProtocol('https:'), true);
  assert.equal(isAllowedProtocol('file:'), false);
  assert.equal(isAllowedProtocol('ftp:'), false);
  assert.equal(isAllowedProtocol('gopher:'), false);
  assert.equal(isAllowedProtocol('data:'), false);
});

test('public host resolving to public IP is allowed and pinned', async () => {
  const d = await guardHost('example.com', fakeResolver({ 'example.com': ['93.184.216.34'] }));
  assert.equal(d.allowed, true);
  assert.equal(d.pinnedIp, '93.184.216.34');
  assert.equal(d.pinnedFamily, 4);
});

test('host resolving to a private IP is refused (DNS-rebinding defense)', async () => {
  const d = await guardHost('evil.example', fakeResolver({ 'evil.example': ['10.0.0.5'] }));
  assert.equal(d.allowed, false);
  assert.equal(d.category, 'private');
  assert.match(d.reason, /10\.0\.0\.5/);
});

test('host resolving to the cloud metadata IP is refused', async () => {
  const d = await guardHost('rebind.example', fakeResolver({ 'rebind.example': ['169.254.169.254'] }));
  assert.equal(d.allowed, false);
  assert.equal(d.category, 'link-local');
});

test('mixed public+private resolution is refused entirely', async () => {
  const d = await guardHost('split.example', fakeResolver({ 'split.example': ['8.8.8.8', '127.0.0.1'] }));
  assert.equal(d.allowed, false, 'any internal address must block the whole host');
  assert.equal(d.category, 'loopback');
});

test('IP literal hosts are classified without DNS', async () => {
  const pub = await guardHost('1.1.1.1');
  assert.equal(pub.allowed, true);
  assert.equal(pub.pinnedIp, '1.1.1.1');

  const loop = await guardHost('127.0.0.1');
  assert.equal(loop.allowed, false);
  assert.equal(loop.category, 'loopback');

  const meta = await guardHost('169.254.169.254');
  assert.equal(meta.allowed, false);
  assert.equal(meta.category, 'link-local');
});

test('loopback and internal names are refused before DNS', async () => {
  const reject = (h: string) => guardHost(h, async () => { throw new Error('should not resolve'); });
  assert.equal((await reject('localhost')).allowed, false);
  assert.equal((await reject('foo.localhost')).allowed, false);
  assert.equal((await reject('printer.local')).allowed, false);
  assert.equal((await reject('db.internal')).allowed, false);
});

test('DNS failure is a refusal, not a crash', async () => {
  const d = await guardHost('does-not-exist.example', fakeResolver({}));
  assert.equal(d.allowed, false);
  assert.equal(d.category, 'dns-error');
});

test('decimal/hex IP forms are normalised by URL parser before reaching the guard', () => {

  assert.equal(new URL('http://2130706433/').hostname, '127.0.0.1');
  assert.equal(new URL('http://0x7f000001/').hostname, '127.0.0.1');
  assert.equal(new URL('http://017700000001/').hostname, '127.0.0.1');
});
