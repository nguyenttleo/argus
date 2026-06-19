import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createReputationRegistry } from './registry.ts';
import { localFeedProvider } from './localfeed.ts';
import type { ReputationProvider } from './provider.ts';
import type { EngineConfig } from '../config.ts';

const cfg: EngineConfig = {
  reputationTimeoutMs: 1000,
  fetchTimeoutMs: 1000,
  maxFetchBytes: 1024,
};

test('local feed flags a bundled bad host and clears a clean one', async () => {
  const reg = createReputationRegistry(cfg, [localFeedProvider()]);
  const bad = await reg.checkUrl('http://testsafebrowsing.appspot.com/');
  assert.equal(bad[0]?.listed, true);
  const good = await reg.checkUrl('https://www.google.com/');
  assert.equal(good[0]?.listed, false);
  assert.equal(good[0]?.available, true);
});

test('local feed flags the EICAR hash', async () => {
  const reg = createReputationRegistry(cfg, [localFeedProvider()]);
  const r = await reg.checkHash('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');
  assert.equal(r[0]?.listed, true);
});

test('a throwing provider degrades to unavailable, never crashes the scan', async () => {
  const boom: ReputationProvider = {
    name: 'Boom',
    configured: true,
    async checkUrl() {
      throw new Error('kaboom');
    },
  };
  const reg = createReputationRegistry(cfg, [boom]);
  const r = await reg.checkUrl('http://example.com');
  assert.equal(r[0]?.available, false);
  assert.equal(r[0]?.source, 'unavailable');
});

test('results are cached - provider is hit once, second read is a cache hit', async () => {
  let calls = 0;
  const counting: ReputationProvider = {
    name: 'Counter',
    configured: true,
    async checkUrl() {
      calls++;
      return { provider: 'Counter', available: true, listed: false, detail: 'ok', source: 'live' };
    },
  };
  const reg = createReputationRegistry(cfg, [counting]);
  const a = await reg.checkUrl('http://example.com');
  const b = await reg.checkUrl('http://example.com');
  assert.equal(calls, 1, 'provider should only be queried once');
  assert.equal(a[0]?.source, 'live');
  assert.equal(b[0]?.source, 'cache');
});

test('configuredProviders reflects which have keys', () => {
  const reg = createReputationRegistry(cfg, [
    localFeedProvider(),
    { name: 'NoKey', configured: false, async checkUrl() { return { provider: 'NoKey', available: false, listed: false }; } },
  ]);
  assert.deepEqual(reg.configuredProviders(), ['Local sample feed']);
});
