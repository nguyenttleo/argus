/**
 * DNS intelligence for the registrable domain: MX / NS / TXT records and the
 * presence of SPF + DMARC email-authentication policies. Established organisations
 * almost always publish these; throwaway phishing domains usually don't. The
 * resolver is injectable so the logic is unit-testable offline.
 */

import dnsPromises from 'node:dns/promises';
import type { DnsInfo, Signal } from '@argus/shared';

export interface DnsResolver {
  resolveMx(host: string): Promise<{ exchange: string; priority: number }[]>;
  resolveNs(host: string): Promise<string[]>;
  resolveTxt(host: string): Promise<string[][]>;
}

const defaultResolver: DnsResolver = {
  resolveMx: (h) => dnsPromises.resolveMx(h),
  resolveNs: (h) => dnsPromises.resolveNs(h),
  resolveTxt: (h) => dnsPromises.resolveTxt(h),
};

export async function gatherDns(domain: string, resolver: DnsResolver = defaultResolver, timeoutMs = 4000): Promise<DnsInfo> {
  const errors: string[] = [];
  const withTimeout = <T>(p: Promise<T>): Promise<T> =>
    Promise.race([p, new Promise<T>((_, rej) => setTimeout(() => rej(new Error('timeout')), timeoutMs))]);
  const safe = async <T>(p: Promise<T>, fallback: T, label: string): Promise<T> => {
    try {
      return await withTimeout(p);
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code ?? (e as Error).message;
      // ENODATA / ENOTFOUND are normal (record simply absent) - only note real errors
      if (code !== 'ENODATA' && code !== 'ENOTFOUND') errors.push(`${label}: ${code}`);
      return fallback;
    }
  };

  const [mxR, nsR, txtR, dmarcR] = await Promise.all([
    safe(resolver.resolveMx(domain), [], 'mx'),
    safe(resolver.resolveNs(domain), [], 'ns'),
    safe(resolver.resolveTxt(domain), [], 'txt'),
    safe(resolver.resolveTxt(`_dmarc.${domain}`), [], 'dmarc'),
  ]);

  const txt = txtR.map((parts) => parts.join(''));
  const hasSpf = txt.some((t) => /^v=spf1/i.test(t.trim()));
  const dmarcTxt = dmarcR.map((parts) => parts.join('')).find((t) => /^v=DMARC1/i.test(t.trim()));
  const dmarcPolicy = dmarcTxt ? /\bp=([a-z]+)/i.exec(dmarcTxt)?.[1] : undefined;

  return {
    mx: mxR.map((m) => m.exchange).slice(0, 8),
    ns: nsR.slice(0, 8),
    txt: txt.slice(0, 8),
    hasSpf,
    hasDmarc: !!dmarcTxt,
    dmarcPolicy,
    errors,
  };
}

export function dnsSignals(
  dns: DnsInfo,
  ctx: { isIpHost: boolean; registrableDomain?: string; impersonatesBrand: boolean },
): Signal[] {
  const out: Signal[] = [];
  if (ctx.isIpHost || !ctx.registrableDomain) return out;
  if (dns.errors.length > 0) return out; // resolution problems - don't infer from partial data

  // Missing email authentication is a weak signal on its own, but meaningful when
  // a page also tries to look like a known brand (real brands publish SPF/DMARC).
  if (!dns.hasSpf && !dns.hasDmarc) {
    out.push({
      id: 'dns.no_email_auth',
      category: 'network',
      title: 'No SPF or DMARC records published',
      detail:
        'The domain publishes neither SPF nor DMARC email-authentication records. Real organisations almost always do; their absence is common on disposable phishing domains.',
      severity: ctx.impersonatesBrand ? 'medium' : 'low',
      weight: ctx.impersonatesBrand ? 28 : 13,
      confidence: 0.5,
      evidence: { hasSpf: dns.hasSpf, hasDmarc: dns.hasDmarc },
    });
  } else if (!dns.hasDmarc && ctx.impersonatesBrand) {
    out.push({
      id: 'dns.no_dmarc',
      category: 'network',
      title: 'No DMARC policy',
      detail: 'The domain has no DMARC policy, unusual for a brand-grade domain it appears to imitate.',
      severity: 'low',
      weight: 16,
      confidence: 0.45,
    });
  }
  return out;
}
