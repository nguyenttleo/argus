/**
 * Optional behavioural detonation via the Tartarus sandbox (spec v3).
 *
 * Argus never runs a sample on the host. When (and only when) the operator opts in
 * AND a `TARTARUS_URL` is configured, script payloads (py/js) can be shipped to the
 * isolated Tartarus sandbox, which executes them and returns a trace we mine for
 * behavioural IOCs. Any failure degrades to "unavailable" - detonation is additive,
 * never required. Binaries are not detonated by this integration.
 */

import type { DetonationResult, Ioc } from '@argus/shared';
import type { EngineConfig } from '../config.ts';
import { extractIocs } from './static.ts';

export async function tartarusDetonate(
  bytes: Uint8Array,
  filename: string,
  config: EngineConfig,
): Promise<DetonationResult> {
  if (!config.tartarusUrl) {
    return { available: false, ran: false, source: 'unavailable', detail: 'TARTARUS_URL not configured' };
  }
  const ext = filename.split('.').pop()?.toLowerCase();
  const language = ext === 'py' ? 'python' : ext === 'js' || ext === 'mjs' ? 'javascript' : undefined;
  if (!language) {
    return { available: true, ran: false, source: 'tartarus', detail: 'only python/js payloads are detonated by this integration' };
  }

  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 15_000);
  try {
    const res = await fetch(`${config.tartarusUrl.replace(/\/$/, '')}/run`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ language, code: Buffer.from(bytes).toString('utf8') }),
      signal: ctrl.signal,
    });
    if (!res.ok) {
      return { available: false, ran: false, source: 'unavailable', detail: `Tartarus responded ${res.status}` };
    }
    const data: unknown = await res.json().catch(() => ({}));
    const traceText = JSON.stringify(data);
    const iocs: Ioc[] = extractIocs(traceText);
    return {
      available: true,
      ran: true,
      source: 'tartarus',
      detail: `executed in Tartarus sandbox; ${iocs.length} indicator(s) mined from the trace`,
      iocs,
    };
  } catch (e) {
    return { available: false, ran: false, source: 'unavailable', detail: `detonation error: ${(e as Error).message}` };
  } finally {
    clearTimeout(timer);
  }
}
