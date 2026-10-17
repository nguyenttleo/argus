export interface EngineConfig {
  googleSafeBrowsingKey?: string;
  virusTotalKey?: string;
  phishTankKey?: string;

  urlhausAuthKey?: string;

  abuseChAuthKey?: string;

  reputationTimeoutMs: number;

  tartarusUrl?: string;

  fetchTimeoutMs: number;
  maxFetchBytes: number;
}

function num(v: string | undefined, fallback: number): number {
  const n = v ? Number(v) : NaN;
  return Number.isFinite(n) ? n : fallback;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): EngineConfig {
  return {
    googleSafeBrowsingKey: env.GOOGLE_SAFE_BROWSING_API_KEY || undefined,
    virusTotalKey: env.VIRUSTOTAL_API_KEY || undefined,
    phishTankKey: env.PHISHTANK_API_KEY || undefined,
    urlhausAuthKey: env.URLHAUS_AUTH_KEY || undefined,
    abuseChAuthKey: env.ABUSE_CH_AUTH_KEY || env.URLHAUS_AUTH_KEY || undefined,
    reputationTimeoutMs: num(env.ARGUS_REPUTATION_TIMEOUT_MS, 6000),
    tartarusUrl: env.TARTARUS_URL || undefined,
    fetchTimeoutMs: num(env.ARGUS_FETCH_TIMEOUT_MS, 8000),
    maxFetchBytes: num(env.ARGUS_MAX_FETCH_BYTES, 2 * 1024 * 1024),
  };
}
