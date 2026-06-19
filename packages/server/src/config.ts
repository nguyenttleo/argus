import { loadConfig, type EngineConfig } from '@argus/engine';

export interface ServerConfig extends EngineConfig {
  port: number;
  host: string;
  dataDir: string;
  dbPath: string;
  quarantineEnabled: boolean;
  quarantineTtlMs: number;
  maxUploadBytes: number;
  ipHashSecret: string;
  corsOrigin: string;
  rateLimitMax: number;
  rateLimitWindowMs: number;
  /** TTL for the in-memory full-scan result cache (repeat scans return instantly). */
  scanCacheTtlMs: number;
  /** default options for URL scans when the request doesn't specify */
  urlFetchDefault: boolean;
  reputationDefault: boolean;
}

function num(v: string | undefined, fallback: number): number {
  const n = v ? Number(v) : NaN;
  return Number.isFinite(n) ? n : fallback;
}
function bool(v: string | undefined, fallback: boolean): boolean {
  if (v === undefined) return fallback;
  return v === '1' || v.toLowerCase() === 'true';
}

export function loadServerConfig(env: NodeJS.ProcessEnv = process.env): ServerConfig {
  const dataDir = env.ARGUS_DATA_DIR || '.data';
  return {
    ...loadConfig(env),
    port: num(env.PORT, 8089),
    host: env.HOST || '127.0.0.1',
    dataDir,
    dbPath: env.ARGUS_DB_PATH || `${dataDir}/argus.sqlite`,
    quarantineEnabled: bool(env.ARGUS_QUARANTINE, false),
    quarantineTtlMs: num(env.ARGUS_QUARANTINE_TTL_MS, 24 * 60 * 60 * 1000),
    maxUploadBytes: num(env.ARGUS_MAX_UPLOAD_BYTES, 32 * 1024 * 1024),
    ipHashSecret: env.ARGUS_IP_HASH_SECRET || 'argus-dev-ip-salt',
    corsOrigin: env.ARGUS_CORS_ORIGIN || 'http://localhost:3000',
    rateLimitMax: num(env.ARGUS_RATE_LIMIT_MAX, 60),
    rateLimitWindowMs: num(env.ARGUS_RATE_LIMIT_WINDOW_MS, 60_000),
    scanCacheTtlMs: num(env.ARGUS_SCAN_CACHE_TTL_MS, 5 * 60_000),
    urlFetchDefault: bool(env.ARGUS_URL_FETCH_DEFAULT, true),
    reputationDefault: bool(env.ARGUS_REPUTATION_DEFAULT, true),
  };
}
