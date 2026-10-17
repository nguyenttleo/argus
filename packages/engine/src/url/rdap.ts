import type { RdapInfo, Signal } from '@argus/shared';

const ENDPOINT = 'https://rdap.org/domain/';

interface RdapEvent {
  eventAction?: string;
  eventDate?: string;
}
interface RdapEntity {
  roles?: string[];
  vcardArray?: unknown;
  handle?: string;
}
interface RdapResponse {
  events?: RdapEvent[];
  entities?: RdapEntity[];
  status?: string[];
}

export async function rdapLookup(
  domain: string,
  opts: { timeoutMs?: number; fetchFn?: typeof fetch; now?: () => number } = {},
): Promise<RdapInfo> {
  const fetchFn = opts.fetchFn ?? fetch;
  const now = opts.now ?? Date.now;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), opts.timeoutMs ?? 5000);
  try {
    const res = await fetchFn(`${ENDPOINT}${encodeURIComponent(domain)}`, {
      signal: ctrl.signal,
      headers: { accept: 'application/rdap+json' },
      redirect: 'follow',
    });
    if (res.status === 404) return { available: true, detail: 'domain not found in RDAP', source: 'live' };
    if (!res.ok) return { available: false, detail: `RDAP status ${res.status}`, source: 'unavailable' };
    const data = (await res.json()) as RdapResponse;

    const regEvent = data.events?.find((e) => e.eventAction === 'registration');
    const registeredAt = regEvent?.eventDate;
    const ageDays = registeredAt ? Math.floor((now() - new Date(registeredAt).getTime()) / 86_400_000) : undefined;
    const registrar = data.entities?.find((e) => e.roles?.includes('registrar'))?.handle;

    return {
      available: true,
      registeredAt,
      ageDays: typeof ageDays === 'number' && Number.isFinite(ageDays) ? ageDays : undefined,
      registrar,
      statuses: data.status,
      source: 'live',
    };
  } catch (e) {
    return { available: false, detail: `RDAP error: ${(e as Error).message}`, source: 'unavailable' };
  } finally {
    clearTimeout(timer);
  }
}

const BAD_STATUSES = ['pending delete', 'client hold', 'server hold', 'redemption'];

export function rdapSignals(info: RdapInfo): Signal[] {
  const out: Signal[] = [];
  if (!info.available) return out;

  if (typeof info.ageDays === 'number') {
    const d = info.ageDays;
    if (d < 0) {
      // Skip invalid dates.
    } else if (d <= 14) {
      out.push(ageSignal(d, 'high', 52, 0.82));
    } else if (d <= 90) {
      out.push(ageSignal(d, 'medium', 34, 0.7));
    } else if (d <= 365) {
      out.push(ageSignal(d, 'low', 16, 0.55));
    }
  }

  const bad = (info.statuses ?? []).filter((s) => BAD_STATUSES.some((b) => s.toLowerCase().includes(b)));
  if (bad.length) {
    out.push({
      id: 'rdap.bad_status',
      category: 'reputation',
      title: `Domain in a problematic registry state (${bad.join(', ')})`,
      detail: `The registry reports the domain status as: ${bad.join(', ')}. Domains on hold or pending deletion are frequently abused or abandoned.`,
      severity: 'medium',
      weight: 30,
      confidence: 0.6,
      evidence: { statuses: info.statuses },
    });
  }
  return out;
}

function ageSignal(days: number, severity: 'low' | 'medium' | 'high', weight: number, confidence: number): Signal {
  const human = days <= 1 ? 'today' : `${days} day${days === 1 ? '' : 's'} ago`;
  return {
    id: 'rdap.young_domain',
    category: 'reputation',
    title: `Recently registered domain (${human})`,
    detail: `This domain was registered ${human}. The overwhelming majority of phishing and malware domains are brand-new; long-lived domains are far safer. Age is one of the strongest single indicators of intent.`,
    severity,
    weight,
    confidence,
    evidence: { ageDays: days },
  };
}
