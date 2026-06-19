import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeUrl, InvalidUrlError } from './analyze.ts';
import type { FetchResult } from './fetcher.ts';
import type { ReputationRegistry } from '../reputation/registry.ts';
import type { ReputationResult } from '@argus/shared';

const cfg = { reputationTimeoutMs: 500, fetchTimeoutMs: 500, maxFetchBytes: 1024 };
const fixedDeps = { config: cfg, now: () => new Date('2026-01-01T00:00:00Z'), idGen: () => 'test-id' };

const fakeRegistry = (results: ReputationResult[]): ReputationRegistry => ({
  configuredProviders: () => results.map((r) => r.provider),
  checkUrl: async () => results,
  checkHash: async () => results,
});

const fakeFetch =
  (res: Partial<FetchResult>) =>
  async (): Promise<FetchResult> => ({
    ok: true,
    finalUrl: 'https://example.com/',
    redirects: [],
    bytes: 0,
    resolvedIps: [],
    ...res,
  });

test('benign popular URL ⇒ safe', async () => {
  const r = await analyzeUrl('https://www.google.com/', {}, fixedDeps);
  assert.equal(r.verdict, 'safe');
  assert.equal(r.kind, 'url');
  assert.ok(r.signals.some((s) => s.id === 'url.popular_allowlist' && s.mitigates));
});

test('crafted phishing URL ⇒ malicious from heuristics alone', async () => {
  const r = await analyzeUrl('http://google.com@secure-paypa1-login.tk/webscr?cmd=verify', {}, fixedDeps);
  assert.equal(r.verdict, 'malicious');
  assert.ok(r.signals.length >= 3);
  assert.match(r.summary, /caution|Do not/i);
});

test('a Safe Browsing hit is decisive malicious', async () => {
  const reg = fakeRegistry([
    { provider: 'Google Safe Browsing', available: true, listed: true, categories: ['SOCIAL_ENGINEERING'], detail: 'flagged', source: 'live' },
  ]);
  const r = await analyzeUrl('http://totally-normal-site.example/', { reputation: true }, { ...fixedDeps, registry: reg });
  assert.equal(r.verdict, 'malicious');
  assert.ok(r.score >= 90);
  assert.equal(r.detail.kind, 'url');
  if (r.detail.kind === 'url') assert.equal(r.detail.reputation.length, 1);
});

test('reputation requested but nothing configured ⇒ honest coverage note', async () => {
  const reg = fakeRegistry([{ provider: 'X', available: false, listed: false, source: 'unavailable' }]);
  const r = await analyzeUrl('https://www.google.com/', { reputation: true }, { ...fixedDeps, registry: reg });
  assert.ok(r.signals.some((s) => s.id === 'meta.reputation_unavailable'));
});

test('SSRF-guard block during fetch surfaces a network signal, no crash', async () => {
  const r = await analyzeUrl(
    'http://internal.example/',
    { fetch: true },
    { ...fixedDeps, fetchImpl: fakeFetch({ ok: false, error: 'blocked', blocked: { url: 'http://internal.example/', reason: 'resolves to 10.0.0.1 (private)', category: 'private' } }) },
  );
  assert.ok(r.signals.some((s) => s.id === 'net.fetch_blocked'));
  assert.equal(r.detail.kind, 'url');
  if (r.detail.kind === 'url') assert.equal(r.detail.fetched, false);
});

test('a destination serving an executable is flagged via content-type', async () => {
  const r = await analyzeUrl(
    'http://files.example/download',
    { fetch: true },
    { ...fixedDeps, fetchImpl: fakeFetch({ contentType: 'application/x-msdownload', finalUrl: 'http://files.example/download', bytes: 12345 }) },
  );
  assert.ok(r.signals.some((s) => s.id === 'net.serves_executable'));
});

test('cross-domain redirect re-analyzes the final URL', async () => {
  const r = await analyzeUrl(
    'https://bit.ly/abc',
    { fetch: true },
    { ...fixedDeps, fetchImpl: fakeFetch({ finalUrl: 'http://paypa1.com/login', redirects: [{ url: 'https://bit.ly/abc', status: 302, location: 'http://paypa1.com/login' }] }) },
  );
  assert.ok(r.signals.some((s) => s.id === 'net.cross_domain_redirect'));
  // the typosquat on the *final* domain should now be present (paypa1 ≈ paypal)
  assert.ok(r.signals.some((s) => s.id === 'url.typosquat'));
  assert.equal(r.verdict, 'malicious');
});

test('invalid URL rejects with InvalidUrlError', async () => {
  await assert.rejects(() => analyzeUrl('http://', {}, fixedDeps), InvalidUrlError);
});

test('report shape is complete', async () => {
  const r = await analyzeUrl('https://www.google.com/', {}, fixedDeps);
  assert.equal(r.id, 'test-id');
  assert.equal(r.engineVersion, '1.0.0');
  assert.equal(r.createdAt, '2026-01-01T00:00:00.000Z');
  assert.ok(typeof r.score === 'number');
  assert.ok(typeof r.confidence === 'number');
  assert.ok(r.iocs.some((i) => i.type === 'url'));
});
