import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyIp, isPublicIp, ipv4ToInt, ipv6ToBigInt, isIpLiteral } from './ip.ts';

test('public IPv4 addresses are public', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '93.184.216.34', '140.82.121.4']) {
    assert.equal(isPublicIp(ip), true, `${ip} should be public`);
  }
});

test('private / loopback / link-local IPv4 are blocked', () => {
  const blocked: Array<[string, string]> = [
    ['127.0.0.1', 'loopback'],
    ['127.255.255.254', 'loopback'],
    ['10.0.0.1', 'private'],
    ['10.255.255.255', 'private'],
    ['172.16.0.1', 'private'],
    ['172.31.255.255', 'private'],
    ['192.168.1.1', 'private'],
    ['169.254.169.254', 'link-local'], // ← cloud metadata endpoint
    ['169.254.0.1', 'link-local'],
    ['100.64.0.1', 'cgnat'],
    ['0.0.0.0', 'this-network'],
    ['255.255.255.255', 'broadcast'],
    ['224.0.0.1', 'multicast'],
    ['240.0.0.1', 'reserved'],
    ['198.18.0.1', 'benchmark'],
    ['192.0.2.5', 'documentation'],
  ];
  for (const [ip, cat] of blocked) {
    const c = classifyIp(ip);
    assert.equal(c.public, false, `${ip} must NOT be public`);
    assert.equal(c.category, cat, `${ip} category`);
  }
});

test('172.32.0.1 is public (just outside 172.16/12)', () => {
  assert.equal(isPublicIp('172.32.0.1'), true);
});

test('public IPv6 is public; loopback/ULA/link-local blocked', () => {
  assert.equal(isPublicIp('2606:4700:4700::1111'), true); // cloudflare
  assert.equal(classifyIp('::1').public, false);
  assert.equal(classifyIp('::1').category, 'loopback');
  assert.equal(classifyIp('fe80::1').category, 'link-local');
  assert.equal(classifyIp('fc00::1').category, 'unique-local');
  assert.equal(classifyIp('fd12:3456::1').category, 'unique-local');
  assert.equal(classifyIp('ff02::1').category, 'multicast');
});

test('IPv4-mapped IPv6 unwraps and re-checks the embedded v4', () => {
  // ::ffff:169.254.169.254 must still be blocked as link-local
  const c = classifyIp('::ffff:169.254.169.254');
  assert.equal(c.public, false);
  assert.match(c.reason, /169\.254\.169\.254/);
  // ::ffff:127.0.0.1 blocked
  assert.equal(classifyIp('::ffff:127.0.0.1').public, false);
  // ::ffff:8.8.8.8 is public
  assert.equal(classifyIp('::ffff:8.8.8.8').public, true);
});

test('NAT64 embedding a private v4 is blocked', () => {
  assert.equal(classifyIp('64:ff9b::10.0.0.1').public, false);
  assert.equal(classifyIp('64:ff9b::8.8.8.8').public, true);
});

test('ipv4ToInt parses and rejects', () => {
  assert.equal(ipv4ToInt('0.0.0.0'), 0);
  assert.equal(ipv4ToInt('255.255.255.255'), 0xffffffff);
  assert.equal(ipv4ToInt('1.2.3.4'), (1 << 24) | (2 << 16) | (3 << 8) | 4);
  assert.equal(ipv4ToInt('256.0.0.1'), null);
  assert.equal(ipv4ToInt('1.2.3'), null);
  assert.equal(ipv4ToInt('a.b.c.d'), null);
});

test('ipv6ToBigInt expands :: correctly', () => {
  assert.equal(ipv6ToBigInt('::1'), 1n);
  assert.equal(ipv6ToBigInt('::'), 0n);
  assert.equal(ipv6ToBigInt('2001:db8::1'), (0x20010db8n << 96n) | 1n);
  assert.equal(ipv6ToBigInt('not:an:ip'), null);
});

test('isIpLiteral distinguishes IPs from hostnames', () => {
  assert.equal(isIpLiteral('127.0.0.1'), true);
  assert.equal(isIpLiteral('::1'), true);
  assert.equal(isIpLiteral('example.com'), false);
  assert.equal(isIpLiteral('localhost'), false);
});

test('junk input is classified invalid, never public', () => {
  assert.equal(classifyIp('hello').public, false);
  assert.equal(classifyIp('').public, false);
  assert.equal(classifyIp('999.999.999.999').public, false);
});
