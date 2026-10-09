import type { ReputationResult } from '@argus/shared';
import { fetchJson, unavailable, type ReputationProvider } from './provider.ts';


const HOST_ENDPOINT = 'https://urlhaus-api.abuse.ch/v1/host/';

interface UrlhausResponse {
  query_status?: string;
  urls?: Array<{ url_status?: string; threat?: string }>;
  blacklists?: Record<string, string>;
}

export function urlhausProvider(authKey: string | undefined, timeoutMs: number): ReputationProvider {
  return {
    name: 'URLhaus',
    configured: !!authKey,
    async checkUrl(url, signal): Promise<ReputationResult> {
      if (!authKey) return unavailable('URLhaus', 'no URLHAUS_AUTH_KEY configured');
      let host: string;
      try {
        host = new URL(url).hostname;
      } catch {
        return unavailable('URLhaus', 'unparseable URL');
      }
      const res = await fetchJson(
        HOST_ENDPOINT,
        {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded', 'Auth-Key': authKey },
          body: new URLSearchParams({ host }).toString(),
        },
        signal,
        timeoutMs,
      );
      if (!res) return unavailable('URLhaus', 'network error or timeout');
      if (res.status === 401 || res.status === 403) return unavailable('URLhaus', 'auth rejected');
      const data = res.json as UrlhausResponse;
      if (!data || data.query_status === undefined) return unavailable('URLhaus', `unexpected response (${res.status})`);
      if (data.query_status === 'no_results') {
        return { provider: 'URLhaus', available: true, listed: false, detail: 'not listed on URLhaus', source: 'live' };
      }
      const active = (data.urls ?? []).filter((u) => u.url_status === 'online');
      const threats = [...new Set((data.urls ?? []).map((u) => u.threat).filter(Boolean) as string[])];
      return {
        provider: 'URLhaus',
        available: true,
        listed: (data.urls?.length ?? 0) > 0,
        categories: threats.length ? threats : undefined,
        detail: `${data.urls?.length ?? 0} URLhaus record(s) for this host${active.length ? `, ${active.length} currently online` : ''}`,
        source: 'live',
      };
    },
  };
}
