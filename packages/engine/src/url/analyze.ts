

import { randomUUID } from 'node:crypto';
import {
  buildReport,
  ENGINE_VERSION,
  type DnsInfo,
  type Ioc,
  type RdapInfo,
  type Report,
  type Signal,
  type TlsInfo,
  type UrlScanDetail,
  type UrlScanOptions,
} from '@argus/shared';
import { parse as parseDomain } from 'tldts';
import { loadConfig, type EngineConfig } from '../config.ts';
import { createReputationRegistry, type ReputationRegistry } from '../reputation/registry.ts';
import { analyzeLexical } from './lexical.ts';
import { safeFetch, type FetchResult } from './fetcher.ts';
import { gatherDns, dnsSignals, type DnsResolver } from './dns.ts';
import { rdapLookup, rdapSignals } from './rdap.ts';
import { analyzeContent, contentSignals } from './content.ts';
import { TRUSTED_SSO_IDPS, TRUSTED_SSO_RELYING_PARTIES } from './data.ts';
import type { Resolver } from './ssrf.ts';

export class InvalidUrlError extends Error {}

export interface AnalyzeUrlDeps {
  config?: EngineConfig;
  registry?: ReputationRegistry;
  resolver?: Resolver;
  fetchImpl?: typeof safeFetch;
  dnsResolver?: DnsResolver;
  rdapFetch?: typeof fetch;
  now?: () => Date;
  idGen?: () => string;
}

const EXECUTABLE_CONTENT_TYPES = new Set([
  'application/x-msdownload',
  'application/x-msdos-program',
  'application/x-dosexec',
  'application/vnd.microsoft.portable-executable',
  'application/x-executable',
  'application/x-mach-binary',
  'application/octet-stream',
]);

function normalizeInput(raw: string): string {
  const trimmed = raw.trim();

  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    if (/^[a-z][a-z0-9+.-]*:/i.test(trimmed)) return trimmed;
    return `http://${trimmed}`;
  }
  return trimmed;
}

function tlsSignals(tls: TlsInfo, finalScheme: string): Signal[] {
  const out: Signal[] = [];
  if (finalScheme !== 'https') return out;
  if (tls.selfSigned) {
    out.push({
      id: 'tls.self_signed',
      category: 'tls',
      title: 'Self-signed TLS certificate',
      detail: `The site presents a self-signed certificate (issuer = subject = “${tls.subject ?? '?'}”). Trusted sites use a certificate signed by a recognised authority.`,
      severity: 'medium',
      weight: 34,
      confidence: 0.8,
      evidence: { issuer: tls.issuer, subject: tls.subject },
    });
  } else if (tls.valid === false) {
    out.push({
      id: 'tls.invalid',
      category: 'tls',
      title: 'Invalid TLS certificate',
      detail: `The certificate failed validation${tls.error ? `: ${tls.error}` : ''}. This can mean an expired, mismatched, or untrusted certificate.`,
      severity: 'medium',
      weight: 30,
      confidence: 0.75,
      evidence: { error: tls.error },
    });
  }
  if (typeof tls.daysToExpiry === 'number' && tls.daysToExpiry < 0) {
    out.push({
      id: 'tls.expired',
      category: 'tls',
      title: 'Expired TLS certificate',
      detail: `The certificate expired ${Math.abs(tls.daysToExpiry)} day(s) ago (valid until ${tls.validTo}).`,
      severity: 'medium',
      weight: 28,
      confidence: 0.85,
      evidence: { validTo: tls.validTo, daysToExpiry: tls.daysToExpiry },
    });
  }
  return out;
}

function fetchSignals(fetchRes: FetchResult, inputRegistrable: string | undefined): Signal[] {
  const out: Signal[] = [];

  if (!fetchRes.ok && fetchRes.blocked) {

    out.push({
      id: 'net.fetch_blocked',
      category: 'network',
      title: 'Destination is not publicly reachable',
      detail: `Argus's SSRF guard refused to fetch this URL: ${fetchRes.blocked.reason}. The link points at a private/loopback/blocked address or scheme - unusual for a legitimate public link.`,
      severity: fetchRes.blocked.category === 'protocol' ? 'low' : 'medium',
      weight: fetchRes.blocked.category === 'protocol' ? 14 : 24,
      confidence: 0.7,
      evidence: { reason: fetchRes.blocked.reason, category: fetchRes.blocked.category },
    });
    return out;
  }
  if (!fetchRes.ok) return out;

  if (fetchRes.redirects.length >= 4) {
    out.push({
      id: 'net.long_redirect_chain',
      category: 'network',
      title: `Long redirect chain (${fetchRes.redirects.length} hops)`,
      detail: `The link bounces through ${fetchRes.redirects.length} redirects before landing on ${fetchRes.finalUrl}. Long chains are used to launder reputation and evade scanners.`,
      severity: 'low',
      weight: 18,
      confidence: 0.6,
      evidence: { hops: fetchRes.redirects.map((r) => r.url) },
    });
  }

  if (fetchRes.contentType && EXECUTABLE_CONTENT_TYPES.has(fetchRes.contentType)) {
    out.push({
      id: 'net.serves_executable',
      category: 'content',
      title: 'Link serves a downloadable binary',
      detail: `The destination responded with content-type “${fetchRes.contentType}”, i.e. a file download rather than a web page. Drive-by executable downloads are a common malware-delivery vector.`,
      severity: 'medium',
      weight: 38,
      confidence: 0.65,
      evidence: { contentType: fetchRes.contentType, bytes: fetchRes.bytes },
    });
  }

  if (fetchRes.finalUrl) {
    try {
      const finalScheme = new URL(fetchRes.finalUrl).protocol.replace(':', '');
      if (finalScheme === 'http') {
        out.push({
          id: 'net.plaintext',
          category: 'network',
          title: 'Final page served over unencrypted HTTP',
          detail: `After following redirects the page is served over plain HTTP (${fetchRes.finalUrl}). Any data entered is sent unencrypted.`,
          severity: 'low',
          weight: 14,
          confidence: 0.6,
        });
      }
    } catch {}
  }

  return out;
}

function looksLikeHtml(contentType: string | undefined, body: string): boolean {
  if (contentType) return contentType.includes('html') || contentType.includes('xml');
  return /<!doctype html|<html|<head|<body|<form|<title/i.test(body.slice(0, 1000));
}

function registrableFromUrl(url: string | undefined, base?: string): string | undefined {
  if (!url) return undefined;
  try {
    const href = base ? new URL(url, base).href : url;
    return parseDomain(href).domain ?? undefined;
  } catch {
    return undefined;
  }
}

function isTrustedSsoRedirect(fromDomain: string | undefined, toDomain: string | undefined): boolean {
  return !!fromDomain && !!toDomain && TRUSTED_SSO_RELYING_PARTIES.has(fromDomain) && TRUSTED_SSO_IDPS.has(toDomain);
}

function isTrustedSsoFinalLexicalNoise(signal: Signal): boolean {
  return signal.id === 'url.long' || signal.id === 'url.keywords' || signal.id === 'url.open_redirect';
}

function trustedSsoSignal(fromDomain: string | undefined, toDomain: string | undefined): Signal {
  return {
    id: 'net.trusted_sso_redirect',
    category: 'network',
    title: 'Trusted single sign-on handoff',
    detail: `The link starts on ${fromDomain ?? 'a trusted app'} and hands off to ${toDomain ?? 'a trusted identity provider'} for SSO. Long OAuth/SAML login URLs and cross-domain redirects are expected in this flow.`,
    severity: 'info',
    weight: 70,
    confidence: 0.85,
    mitigates: true,
    evidence: { from: fromDomain, to: toDomain },
  };
}

export async function analyzeUrl(
  rawInput: string,
  options: UrlScanOptions = {},
  deps: AnalyzeUrlDeps = {},
): Promise<Report> {
  const start = performance.now();
  const config = deps.config ?? loadConfig();
  const now = deps.now ?? (() => new Date());
  const idGen = deps.idGen ?? (() => randomUUID());
  const fetchImpl = deps.fetchImpl ?? safeFetch;

  const normalizedInput = normalizeInput(rawInput);
  let lexical: ReturnType<typeof analyzeLexical>;
  try {
    lexical = analyzeLexical(normalizedInput);
  } catch {
    throw new InvalidUrlError(`Not a valid URL: ${rawInput}`);
  }

  const signalsById = new Map<string, Signal>();
  const addSignal = (s: Signal) => {
    const existing = signalsById.get(s.id);
    if (!existing || s.weight > existing.weight) signalsById.set(s.id, s);
  };
  for (const s of lexical.signals) addSignal(s);

  const detail: UrlScanDetail = {
    kind: 'url',
    input: rawInput,
    normalized: lexical.parsed.normalized,
    scheme: lexical.parsed.scheme,
    host: lexical.parsed.host,
    port: lexical.parsed.port,
    path: lexical.parsed.path,
    registrableDomain: lexical.parsed.registrableDomain,
    publicSuffix: lexical.parsed.publicSuffix,
    subdomain: lexical.parsed.subdomain,
    isIpHost: lexical.parsed.isIpHost,
    resolvedIps: [],
    redirects: [],
    fetched: false,
    reputation: [],
  };

  const iocs: Ioc[] = [];
  if (detail.registrableDomain) iocs.push({ type: 'domain', value: detail.registrableDomain });


  const impersonatesBrand =
    signalsById.has('url.typosquat') ||
    signalsById.has('url.brand_in_subdomain') ||
    signalsById.get('url.punycode')?.evidence?.['resembles'] != null;

  const domain = lexical.parsed.registrableDomain;
  const httpScheme = lexical.parsed.scheme === 'http' || lexical.parsed.scheme === 'https';


  const doEnrich = !!options.fetch && httpScheme && !lexical.parsed.isIpHost && !!domain;



  const dnsPromise: Promise<DnsInfo | undefined> = doEnrich
    ? gatherDns(domain!, deps.dnsResolver, config.fetchTimeoutMs).catch(() => undefined)
    : Promise.resolve(undefined);
  const rdapPromise: Promise<RdapInfo | undefined> = doEnrich
    ? rdapLookup(domain!, {
        timeoutMs: config.reputationTimeoutMs,
        fetchFn: deps.rdapFetch,
        now: deps.now ? () => deps.now!().getTime() : undefined,
      }).catch(() => undefined)
    : Promise.resolve(undefined);


  let reputationTarget = lexical.parsed.normalized;
  let fetchBody: string | undefined;
  let pageUrl = lexical.parsed.normalized;
  let trustedSsoFlow = false;
  if (options.fetch && httpScheme) {
    const fetchRes = await fetchImpl(lexical.parsed.normalized, {
      resolver: deps.resolver,
      timeoutMs: config.fetchTimeoutMs,
      maxBytes: config.maxFetchBytes,
    });
    detail.fetched = fetchRes.ok;
    detail.redirects = fetchRes.redirects;
    detail.finalUrl = fetchRes.finalUrl;
    detail.resolvedIps = fetchRes.resolvedIps;
    fetchBody = fetchRes.bodyText;
    pageUrl = fetchRes.finalUrl ?? pageUrl;
    if (!fetchRes.ok) detail.fetchError = fetchRes.error;
    if (fetchRes.status !== undefined) {
      detail.http = {
        status: fetchRes.status,
        server: fetchRes.server,
        contentType: fetchRes.contentType,
        bytes: fetchRes.bytes,
        title: fetchRes.title,
      };
    }
    if (fetchRes.tls) detail.tls = fetchRes.tls;

    for (const s of fetchSignals(fetchRes, detail.registrableDomain)) addSignal(s);
    if (fetchRes.tls && fetchRes.finalUrl) {
      const scheme = (() => {
        try {
          return new URL(fetchRes.finalUrl).protocol.replace(':', '');
        } catch {
          return 'https';
        }
      })();
      for (const s of tlsSignals(fetchRes.tls, scheme)) addSignal(s);
    }



    if (fetchRes.ok && fetchRes.finalUrl && fetchRes.finalUrl !== lexical.parsed.normalized) {
      reputationTarget = fetchRes.finalUrl;
      try {
        const finalLex = analyzeLexical(fetchRes.finalUrl);
        if (finalLex.parsed.registrableDomain && finalLex.parsed.registrableDomain !== detail.registrableDomain) {
          trustedSsoFlow = isTrustedSsoRedirect(detail.registrableDomain, finalLex.parsed.registrableDomain);
          addSignal(
            trustedSsoFlow
              ? trustedSsoSignal(detail.registrableDomain, finalLex.parsed.registrableDomain)
              : {
                  id: 'net.cross_domain_redirect',
                  category: 'network',
                  title: 'Redirects to a different domain',
                  detail: `The link starts on ${detail.registrableDomain ?? detail.host} but ends on ${finalLex.parsed.registrableDomain}. Reputable links rarely hop registered domains.`,
                  severity: 'low',
                  weight: 20,
                  confidence: 0.6,
                  evidence: { from: detail.registrableDomain, to: finalLex.parsed.registrableDomain },
                },
          );
          iocs.push({ type: 'domain', value: finalLex.parsed.registrableDomain });
        }
        for (const s of finalLex.signals) {
          if (trustedSsoFlow && isTrustedSsoFinalLexicalNoise(s)) continue;
          if (!signalsById.has(s.id)) {
            addSignal({ ...s, detail: `After redirect to ${finalLex.parsed.host}: ${s.detail}` });
          }
        }
      } catch {}
    }
  }


  const dns = await dnsPromise;
  if (dns) {
    detail.dns = dns;
    for (const s of dnsSignals(dns, { isIpHost: lexical.parsed.isIpHost, registrableDomain: domain, impersonatesBrand })) addSignal(s);
  }
  const rdap = await rdapPromise;
  if (rdap) {
    detail.rdap = rdap;
    for (const s of rdapSignals(rdap)) addSignal(s);
  }


  if (fetchBody && looksLikeHtml(detail.http?.contentType, fetchBody)) {
    const content = analyzeContent(fetchBody, pageUrl);
    detail.content = content;
    const pageDomain = parseDomain(pageUrl).domain ?? domain ?? undefined;
    const metaRefreshDomain = registrableFromUrl(content.metaRefresh, pageUrl);
    const trustedSsoMetaRefresh =
      trustedSsoFlow &&
      !!pageDomain &&
      !!metaRefreshDomain &&
      TRUSTED_SSO_IDPS.has(pageDomain) &&
      TRUSTED_SSO_IDPS.has(metaRefreshDomain);
    for (const s of contentSignals(content, { registrableDomain: pageDomain ?? undefined })) {
      if (trustedSsoMetaRefresh && s.id === 'content.meta_refresh') continue;
      addSignal(s);
    }
  }


  if (options.reputation) {
    const registry = deps.registry ?? createReputationRegistry(config);
    const results = await registry.checkUrl(reputationTarget);
    detail.reputation = results;
    for (const r of results) {
      if (r.available && r.listed) {
        const decisive = r.provider === 'Google Safe Browsing' || r.provider === 'URLhaus';
        addSignal({
          id: `rep.${r.provider.toLowerCase().replace(/[^a-z]+/g, '_')}`,
          category: 'reputation',
          title: `Flagged by ${r.provider}`,
          detail: `${r.provider} reports this destination as malicious: ${r.detail ?? 'listed'}${
            r.categories?.length ? ` (${r.categories.join(', ')})` : ''
          }.`,
          severity: decisive ? 'critical' : 'high',
          weight: decisive ? 95 : 78,
          confidence: decisive ? 0.95 : 0.88,
          evidence: { provider: r.provider, categories: r.categories, source: r.source },
        });
      }
    }
    const anyConfigured = results.some((r) => r.available);
    if (!anyConfigured) {
      addSignal({
        id: 'meta.reputation_unavailable',
        category: 'meta',
        title: 'Reputation feeds unavailable',
        detail:
          'No reputation provider answered (missing API keys or offline). The verdict relies on heuristic + structural analysis only - consider configuring Safe Browsing / URLhaus / VirusTotal keys.',
        severity: 'info',
        weight: 0,
        confidence: 0.5,
      });
    }
  }

  for (const ip of detail.resolvedIps) iocs.push({ type: 'ip', value: ip });
  iocs.push({ type: 'url', value: detail.finalUrl ?? detail.normalized });

  return buildReport({
    id: idGen(),
    kind: 'url',
    target: detail.normalized,
    signals: [...signalsById.values()],
    iocs,
    detail,
    createdAt: now().toISOString(),
    durationMs: Math.round(performance.now() - start),
    engineVersion: ENGINE_VERSION,
  });
}
