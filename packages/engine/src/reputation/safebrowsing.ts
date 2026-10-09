import type { ReputationResult } from '@argus/shared';
import { fetchJson, unavailable, type ReputationProvider } from './provider.ts';


const ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

interface SbResponse {
  matches?: Array<{ threatType?: string; platformType?: string }>;
}

export function safeBrowsingProvider(apiKey: string | undefined, timeoutMs: number): ReputationProvider {
  return {
    name: 'Google Safe Browsing',
    configured: !!apiKey,
    async checkUrl(url, signal): Promise<ReputationResult> {
      if (!apiKey) return unavailable('Google Safe Browsing', 'no GOOGLE_SAFE_BROWSING_API_KEY configured');
      const body = {
        client: { clientId: 'argus-scanner', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      };
      const res = await fetchJson(
        `${ENDPOINT}?key=${encodeURIComponent(apiKey)}`,
        { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) },
        signal,
        timeoutMs,
      );
      if (!res) return unavailable('Google Safe Browsing', 'network error or timeout');
      if (res.status === 400 || res.status === 403) return unavailable('Google Safe Browsing', 'key rejected or invalid request');
      if (res.status !== 200) return unavailable('Google Safe Browsing', `unexpected status ${res.status}`);
      const data = res.json as SbResponse;
      const matches = data?.matches ?? [];
      const types = [...new Set(matches.map((m) => m.threatType).filter(Boolean) as string[])];
      return {
        provider: 'Google Safe Browsing',
        available: true,
        listed: matches.length > 0,
        categories: types.length ? types : undefined,
        detail: matches.length ? `flagged as ${types.join(', ')}` : 'not flagged by Safe Browsing',
        source: 'live',
      };
    },
  };
}
