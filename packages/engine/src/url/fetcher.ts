import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import type { RedirectHop, TlsInfo } from '@argus/shared';
import { guardHost, isAllowedProtocol, type Resolver } from './ssrf.ts';

export interface FetchOptions {
  maxRedirects?: number;
  timeoutMs?: number;
  maxBytes?: number;
  userAgent?: string;
  resolver?: Resolver;
}

export interface FetchResult {
  ok: boolean;
  finalUrl: string;
  redirects: RedirectHop[];
  status?: number;
  headers?: Record<string, string | string[] | undefined>;
  server?: string;
  contentType?: string;
  bytes: number;
  title?: string;
  tls?: TlsInfo;
  bodyText?: string;
  error?: string;

  resolvedIps: string[];

  blocked?: { url: string; reason: string; category?: string };
}

const DEFAULTS = {
  maxRedirects: 8,
  timeoutMs: 8000,
  maxBytes: 2 * 1024 * 1024,
  userAgent: 'ArgusScanner/1.0 (+defensive URL analysis; bytes read, never executed)',
};

const REDIRECT_CODES = new Set([301, 302, 303, 307, 308]);

export function extractTitle(html: string): string | undefined {
  const m = /<title[^>]*>([\s\S]{0,300}?)<\/title>/i.exec(html);
  if (!m) return undefined;
  return m[1]!.replace(/\s+/g, ' ').trim().slice(0, 200) || undefined;
}

function certToTls(socket: import('node:tls').TLSSocket): TlsInfo {
  const cert = socket.getPeerCertificate(false);
  const authorized = socket.authorized;
  const authError = (socket as { authorizationError?: Error }).authorizationError;
  if (!cert || Object.keys(cert).length === 0) {
    return { valid: false, error: 'no certificate presented' };
  }
  const validTo = cert.valid_to ? new Date(cert.valid_to) : undefined;
  const validFrom = cert.valid_from ? new Date(cert.valid_from) : undefined;
  const daysToExpiry = validTo ? Math.round((validTo.getTime() - Date.now()) / 86_400_000) : undefined;
  const dn = (v: string | string[] | undefined): string | undefined =>
    Array.isArray(v) ? v.join(', ') : v;
  const issuerCN = dn(cert.issuer?.CN) ?? dn(cert.issuer?.O);
  const subjectCN = dn(cert.subject?.CN) ?? dn(cert.subject?.O);
  const selfSigned =
    !!issuerCN && !!subjectCN && JSON.stringify(cert.issuer) === JSON.stringify(cert.subject);
  return {
    valid: authorized === true,
    issuer: issuerCN,
    subject: subjectCN,
    validFrom: validFrom?.toISOString(),
    validTo: validTo?.toISOString(),
    daysToExpiry,
    san: cert.subjectaltname ? cert.subjectaltname.split(',').map((s) => s.trim()) : undefined,
    protocol: socket.getProtocol() ?? undefined,
    selfSigned,
    error: authorized ? undefined : authError ? String(authError.message ?? authError) : undefined,
  };
}

interface HopResult {
  status: number;
  headers: http.IncomingHttpHeaders;
  location?: string;
  body: Buffer;
  truncated: boolean;
  tls?: TlsInfo;
  pinnedIp: string;
}

export function requestOnce(
  target: URL,
  pinnedIp: string,
  pinnedFamily: 4 | 6,
  opts: Required<Omit<FetchOptions, 'resolver'>>,
): Promise<HopResult> {
  return new Promise((resolve, reject) => {
    const isHttps = target.protocol === 'https:';
    const mod = isHttps ? https : http;

    const lookup: net.LookupFunction = (_hostname, options, cb) => {

      if (options && typeof options === 'object' && options.all) {
        (cb as unknown as (e: null, a: Array<{ address: string; family: number }>) => void)(null, [
          { address: pinnedIp, family: pinnedFamily },
        ]);
      } else {
        (cb as (e: null, a: string, f: number) => void)(null, pinnedIp, pinnedFamily);
      }
    };

    let settled = false;
    let deadline: ReturnType<typeof setTimeout>;
    let req: http.ClientRequest;
    const done = (val: HopResult) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      resolve(val);
    };
    const fail = (err: Error) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      req?.destroy();
      reject(err);
    };

    req = mod.request(
      target,
      {
        method: 'GET',
        lookup,
        servername: isHttps ? target.hostname : undefined,
        rejectUnauthorized: false,
        headers: {
          'user-agent': opts.userAgent,
          accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
          host: target.host,
        },
        agent: false,
      },
      (res) => {
        const chunks: Buffer[] = [];
        let received = 0;
        let truncated = false;
        let tls: TlsInfo | undefined;
        if (isHttps && res.socket) {
          try {
            tls = certToTls(res.socket as import('node:tls').TLSSocket);
          } catch {}
        }
        const build = (): HopResult => ({
          status: res.statusCode ?? 0,
          headers: res.headers,
          location: res.headers.location,
          body: Buffer.concat(chunks),
          truncated,
          tls,
          pinnedIp,
        });
        res.on('data', (c: Buffer) => {
          if (received >= opts.maxBytes) return;
          received += c.length;
          if (received > opts.maxBytes) {
            truncated = true;
            chunks.push(c.subarray(0, c.length - (received - opts.maxBytes)));
            res.destroy();
          } else {
            chunks.push(c);
          }
        });
        res.on('end', () => done(build()));
        res.on('close', () => {
          if (truncated) done(build());
        });
      },
    );

    deadline = setTimeout(() => fail(new Error(`hard timeout after ${opts.timeoutMs}ms`)), opts.timeoutMs);
    req.setTimeout(opts.timeoutMs, () => fail(new Error(`idle timeout after ${opts.timeoutMs}ms`)));
    req.on('error', (e) => fail(e));
    req.end();
  });
}

export async function safeFetch(rawUrl: string, options: FetchOptions = {}): Promise<FetchResult> {
  const opts = {
    maxRedirects: options.maxRedirects ?? DEFAULTS.maxRedirects,
    timeoutMs: options.timeoutMs ?? DEFAULTS.timeoutMs,
    maxBytes: options.maxBytes ?? DEFAULTS.maxBytes,
    userAgent: options.userAgent ?? DEFAULTS.userAgent,
  };
  const redirects: RedirectHop[] = [];
  const ips = new Set<string>();
  let current: URL;
  try {
    current = new URL(rawUrl);
  } catch {
    return { ok: false, finalUrl: rawUrl, redirects, bytes: 0, error: 'invalid URL', resolvedIps: [] };
  }

  for (let i = 0; i <= opts.maxRedirects; i++) {
    if (!isAllowedProtocol(current.protocol)) {
      return {
        ok: false,
        finalUrl: current.href,
        redirects,
        bytes: 0,
        error: `protocol not allowed: ${current.protocol}`,
        blocked: { url: current.href, reason: `scheme ${current.protocol} is not http/https`, category: 'protocol' },
        resolvedIps: [...ips],
      };
    }

    const guard = await guardHost(current.hostname, options.resolver);
    for (const ip of guard.resolvedIps) ips.add(ip);
    if (!guard.allowed || !guard.pinnedIp) {
      return {
        ok: false,
        finalUrl: current.href,
        redirects,
        bytes: 0,
        error: guard.reason,
        blocked: { url: current.href, reason: guard.reason, category: guard.category },
        resolvedIps: [...ips],
      };
    }

    let hop: HopResult;
    try {
      hop = await requestOnce(current, guard.pinnedIp, guard.pinnedFamily ?? 4, opts);
    } catch (err) {
      return { ok: false, finalUrl: current.href, redirects, bytes: 0, error: (err as Error).message, resolvedIps: [...ips] };
    }

    if (REDIRECT_CODES.has(hop.status) && hop.location && i < opts.maxRedirects) {
      let next: URL;
      try {
        next = new URL(hop.location, current);
      } catch {
        return { ok: false, finalUrl: current.href, redirects, bytes: hop.body.length, error: `bad redirect target: ${hop.location}`, resolvedIps: [...ips] };
      }
      redirects.push({ url: current.href, status: hop.status, location: next.href, ip: guard.pinnedIp });
      current = next;
      continue;
    }

    const contentType = (hop.headers['content-type'] as string | undefined)?.split(';')[0]?.trim();
    const bodyText = hop.body.toString('utf8');
    return {
      ok: true,
      finalUrl: current.href,
      redirects,
      status: hop.status,
      headers: hop.headers,
      server: hop.headers['server'] as string | undefined,
      contentType,
      bytes: hop.body.length,
      title: contentType?.includes('html') ? extractTitle(bodyText) : undefined,
      tls: hop.tls,
      bodyText,
      resolvedIps: [...ips],
    };
  }

  return {
    ok: false,
    finalUrl: current.href,
    redirects,
    bytes: 0,
    error: `too many redirects (>${opts.maxRedirects})`,
    blocked: { url: current.href, reason: `redirect chain exceeded ${opts.maxRedirects} hops`, category: 'redirect-loop' },
    resolvedIps: [...ips],
  };
}
