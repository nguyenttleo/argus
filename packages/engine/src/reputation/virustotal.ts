import type { ReputationResult } from '@argus/shared';
import { fetchJson, unavailable, type ReputationProvider } from './provider.ts';


const ENDPOINT = 'https://www.virustotal.com/api/v3/files/';

interface VtResponse {
  data?: {
    attributes?: {
      last_analysis_stats?: { malicious?: number; suspicious?: number; harmless?: number; undetected?: number };
      meaningful_name?: string;
      popular_threat_classification?: { suggested_threat_label?: string };
    };
  };
}

export function virusTotalProvider(apiKey: string | undefined, timeoutMs: number): ReputationProvider {
  return {
    name: 'VirusTotal',
    configured: !!apiKey,
    async checkHash(sha256, signal): Promise<ReputationResult> {
      if (!apiKey) return unavailable('VirusTotal', 'no VIRUSTOTAL_API_KEY configured');
      const res = await fetchJson(
        `${ENDPOINT}${encodeURIComponent(sha256)}`,
        { method: 'GET', headers: { 'x-apikey': apiKey } },
        signal,
        timeoutMs,
      );
      if (!res) return unavailable('VirusTotal', 'network error or timeout');
      if (res.status === 404) {
        return { provider: 'VirusTotal', available: true, listed: false, detail: 'hash unknown to VirusTotal', source: 'live' };
      }
      if (res.status === 401) return unavailable('VirusTotal', 'API key rejected');
      if (res.status === 429) return unavailable('VirusTotal', 'rate limit / quota exceeded');
      if (res.status !== 200) return unavailable('VirusTotal', `unexpected status ${res.status}`);
      const data = res.json as VtResponse;
      const stats = data?.data?.attributes?.last_analysis_stats ?? {};
      const malicious = stats.malicious ?? 0;
      const suspicious = stats.suspicious ?? 0;
      const label = data?.data?.attributes?.popular_threat_classification?.suggested_threat_label;
      return {
        provider: 'VirusTotal',
        available: true,
        listed: malicious + suspicious > 0,
        categories: label ? [label] : undefined,
        detail:
          malicious + suspicious > 0
            ? `${malicious} engines flagged malicious, ${suspicious} suspicious${label ? ` (${label})` : ''}`
            : 'no engines flagged this hash',
        source: 'live',
      };
    },
  };
}
