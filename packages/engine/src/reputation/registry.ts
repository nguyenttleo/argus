import type { ReputationResult } from '@argus/shared';
import type { EngineConfig } from '../config.ts';
import { TtlCache } from './cache.ts';
import type { ReputationProvider } from './provider.ts';
import { localFeedProvider } from './localfeed.ts';
import { urlhausProvider } from './urlhaus.ts';
import { safeBrowsingProvider } from './safebrowsing.ts';
import { virusTotalProvider } from './virustotal.ts';
import { malwareBazaarProvider } from './malwarebazaar.ts';

const CACHE_TTL_MS = 10 * 60 * 1000; // 10 min

export interface ReputationRegistry {
  /** Names of providers actually configured (have keys / are always-on). */
  configuredProviders(): string[];
  checkUrl(url: string): Promise<ReputationResult[]>;
  checkHash(sha256: string): Promise<ReputationResult[]>;
}

export function createReputationRegistry(
  config: EngineConfig,
  providersOverride?: ReputationProvider[],
): ReputationRegistry {
  const providers: ReputationProvider[] = providersOverride ?? [
    localFeedProvider(),
    urlhausProvider(config.urlhausAuthKey, config.reputationTimeoutMs),
    safeBrowsingProvider(config.googleSafeBrowsingKey, config.reputationTimeoutMs),
    virusTotalProvider(config.virusTotalKey, config.reputationTimeoutMs),
    malwareBazaarProvider(config.abuseChAuthKey, config.reputationTimeoutMs),
  ];
  const cache = new TtlCache<ReputationResult>();

  async function run(
    kind: 'url' | 'hash',
    key: string,
    pick: (p: ReputationProvider) => ReputationProvider['checkUrl'] | ReputationProvider['checkHash'],
  ): Promise<ReputationResult[]> {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), config.reputationTimeoutMs + 500);
    try {
      const results = await Promise.all(
        providers.map(async (p) => {
          const fn = pick(p);
          if (!fn) return null;
          const cacheKey = `${p.name}:${kind}:${key}`;
          const cached = cache.get(cacheKey);
          if (cached) return { ...cached, source: cached.source === 'unavailable' ? cached.source : 'cache' };
          let res: ReputationResult;
          try {
            res = await fn.call(p, key, ctrl.signal);
          } catch {
            res = { provider: p.name, available: false, listed: false, detail: 'provider error', source: 'unavailable' };
          }
          if (res.available) cache.set(cacheKey, res, CACHE_TTL_MS);
          return res;
        }),
      );
      return results.filter((r): r is ReputationResult => r !== null);
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    configuredProviders() {
      return providers.filter((p) => p.configured).map((p) => p.name);
    },
    checkUrl(url) {
      return run('url', url, (p) => p.checkUrl);
    },
    checkHash(sha256) {
      return run('hash', sha256, (p) => p.checkHash);
    },
  };
}
