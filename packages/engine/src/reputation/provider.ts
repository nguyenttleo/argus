import type { ReputationResult } from '@argus/shared';

/**
 * A reputation source. Providers MUST never throw - any failure (no key, network
 * error, timeout, bad response) resolves to `{ available:false }` so a degraded
 * feed can never break a scan.
 */
export interface ReputationProvider {
  name: string;
  /** Configured = has the key/feed it needs to actually answer. */
  configured: boolean;
  checkUrl?(url: string, signal: AbortSignal): Promise<ReputationResult>;
  checkHash?(sha256: string, signal: AbortSignal): Promise<ReputationResult>;
}

export function unavailable(provider: string, detail: string): ReputationResult {
  return { provider, available: false, listed: false, detail, source: 'unavailable' };
}

/** `fetch` with an AbortSignal-based timeout, returning null on any failure. */
export async function fetchJson(
  url: string,
  init: RequestInit,
  outerSignal: AbortSignal,
  timeoutMs: number,
): Promise<{ status: number; json: unknown } | null> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  const onAbort = () => ctrl.abort();
  outerSignal.addEventListener('abort', onAbort, { once: true });
  try {
    const res = await fetch(url, { ...init, signal: ctrl.signal });
    let json: unknown = null;
    const text = await res.text();
    if (text) {
      try {
        json = JSON.parse(text);
      } catch {
        json = text;
      }
    }
    return { status: res.status, json };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
    outerSignal.removeEventListener('abort', onAbort);
  }
}
