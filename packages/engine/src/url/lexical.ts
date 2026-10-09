

import { parse as parseDomain } from 'tldts';
import { domainToUnicode } from 'node:url';
import type { Signal } from '@argus/shared';
import { severityForWeight } from '@argus/shared';
import {
  BRANDS,
  DANGEROUS_EXTS,
  PHISHING_KEYWORDS,
  POPULAR_DOMAINS,
  REDIRECT_PARAMS,
  SUSPICIOUS_TLDS,
  URL_SHORTENERS,
} from './data.ts';
import { isIpLiteral } from './ip.ts';

export interface ParsedUrl {
  input: string;
  normalized: string;
  scheme: string;
  host: string;
  port?: number;
  path: string;
  registrableDomain?: string;
  publicSuffix?: string;
  subdomain?: string;
  isIpHost: boolean;
}

export interface LexicalResult {
  parsed: ParsedUrl;
  signals: Signal[];
}




export function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  let curr = new Array<number>(n + 1);
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      curr[j] = Math.min(prev[j]! + 1, curr[j - 1]! + 1, prev[j - 1]! + cost);
    }
    [prev, curr] = [curr, prev];
  }
  return prev[n]!;
}


const CONFUSABLES: Record<string, string> = {
  а: 'a', е: 'e', о: 'o', р: 'p', с: 'c', у: 'y', х: 'x', ѕ: 's', і: 'i', ј: 'j',
  к: 'k', м: 'm', н: 'h', т: 't', в: 'b', г: 'r', д: 'd', ӏ: 'l',
  α: 'a', ε: 'e', ο: 'o', ρ: 'p', τ: 't', υ: 'u', ν: 'v', ι: 'i', κ: 'k',
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '6': 'g', '7': 't', '8': 'b',
  '@': 'a', $: 's',
};


export function skeleton(s: string): string {
  let out = '';
  for (const ch of s.toLowerCase()) out += CONFUSABLES[ch] ?? ch;
  return out;
}


function scriptsOf(s: string): Set<string> {
  const scripts = new Set<string>();
  if (/\p{Script=Latin}/u.test(s)) scripts.add('Latin');
  if (/\p{Script=Cyrillic}/u.test(s)) scripts.add('Cyrillic');
  if (/\p{Script=Greek}/u.test(s)) scripts.add('Greek');
  if (/\p{Script=Han}/u.test(s)) scripts.add('Han');
  if (/\p{Script=Arabic}/u.test(s)) scripts.add('Arabic');
  if (/\p{Script=Hebrew}/u.test(s)) scripts.add('Hebrew');
  return scripts;
}

function sig(s: Omit<Signal, 'confidence'> & { confidence?: number }): Signal {
  return { confidence: 0.8, ...s };
}



export function analyzeLexical(rawUrl: string): LexicalResult {
  const url = new URL(rawUrl);
  const host = url.hostname;
  const td = parseDomain(url.href);
  const isIpHost = isIpLiteral(host) || td.isIp === true;

  const parsed: ParsedUrl = {
    input: rawUrl,
    normalized: url.href,
    scheme: url.protocol.replace(':', ''),
    host,
    port: url.port ? Number(url.port) : undefined,
    path: url.pathname + url.search,
    registrableDomain: td.domain ?? undefined,
    publicSuffix: td.publicSuffix ?? undefined,
    subdomain: td.subdomain ?? undefined,
    isIpHost,
  };

  const signals: Signal[] = [];
  const add = (s: Omit<Signal, 'confidence'> & { confidence?: number }) => signals.push(sig(s));

  const registrable = td.domain ?? '';
  const sld = registrable.split('.')[0] ?? '';
  const tld = (td.publicSuffix ?? '').split('.').pop() ?? '';
  const fullPath = (url.pathname + url.search).toLowerCase();
  const hostForKeywords = host.toLowerCase();


  if (parsed.scheme !== 'http' && parsed.scheme !== 'https') {
    const scriptable = parsed.scheme === 'javascript' || parsed.scheme === 'vbscript';
    add({
      id: 'url.dangerous_scheme',
      category: 'lexical',
      title: `Non-web URL scheme (${parsed.scheme}:)`,
      detail: scriptable
        ? `This is a "${parsed.scheme}:" URL - clicking it runs code in the page context rather than navigating to a site. A direct script-injection / XSS vector.`
        : `This is a "${parsed.scheme}:" URL, not an ordinary web link. "${parsed.scheme}:" URLs (e.g. data:/file:) can embed entire payloads or pull local resources and are not safe to open blindly.`,
      severity: scriptable ? 'high' : 'medium',
      weight: scriptable ? 55 : 34,
      confidence: 0.8,
      evidence: { scheme: parsed.scheme },
    });
  }


  if (url.username || url.password) {
    add({
      id: 'url.userinfo',
      category: 'lexical',
      title: 'Embedded credentials / “@” in the link',
      detail: `The link carries a userinfo section ("${url.username}${url.password ? ':***' : ''}@"). Everything before the “@” is ignored by the browser - a classic trick to make a hostile host look like a trusted one.`,
      severity: 'high',
      weight: 52,
      confidence: 0.9,
      evidence: { username: url.username, realHost: host },
    });
  }


  if (isIpHost) {
    add({
      id: 'url.ip_host',
      category: 'lexical',
      title: 'Raw IP address instead of a domain',
      detail: `This link points straight at an IP address (${host}) rather than a named domain. Legitimate sites almost always use a domain name; raw IPs are common in phishing and malware C2.`,
      severity: 'high',
      weight: 46,
      confidence: 0.82,
      evidence: { ip: host },
    });
  }


  const labels = host.split('.');
  const puny = labels.filter((l) => l.startsWith('xn--'));
  if (puny.length > 0) {
    const decodeLabel = (l: string): string => {
      if (!l.startsWith('xn--')) return l;
      try {
        return domainToUnicode(l) || l;
      } catch {
        return l;
      }
    };
    const decoded = labels.map(decodeLabel).join('.');
    const mixed = labels.some((l) => l.startsWith('xn--') && scriptsOf(decodeLabel(l)).size > 1);
    const skel = skeleton(decoded.split('.')[0] ?? '');
    const brandHit = Object.entries(BRANDS).find(([b]) => skel === b || levenshtein(skel, b) <= 1);
    add({
      id: 'url.punycode',
      category: 'lexical',
      title: mixed ? 'Homograph attack (mixed-script lookalike domain)' : 'Internationalised (punycode) domain',
      detail: `The hostname uses punycode/IDN (${puny.join(', ')}) which renders as “${decoded}”.${
        mixed ? ' It mixes character scripts - a hallmark of homograph spoofing.' : ''
      }${brandHit ? ` It closely resembles “${brandHit[0]}”.` : ''}`,
      severity: mixed || brandHit ? 'high' : 'medium',
      weight: mixed || brandHit ? 55 : 32,
      confidence: 0.85,
      evidence: { punycode: puny, decoded, mixedScript: mixed, resembles: brandHit?.[0] },
    });
  }


  if (sld && !isIpHost) {
    const skel = skeleton(sld);
    let typo: { brand: string; brandDomain: string; dist: number } | undefined;
    for (const [brand, dom] of Object.entries(BRANDS)) {
      if (registrable === dom) {
        typo = undefined;
        break;
      }
      const d = levenshtein(skel, brand);
      if ((d <= 1 && brand.length >= 4) || skel === brand) {
        if (!typo || d < typo.dist) typo = { brand, brandDomain: dom, dist: d };
      }
    }
    if (typo && registrable !== typo.brandDomain) {
      add({
        id: 'url.typosquat',
        category: 'lexical',
        title: `Look-alike of “${typo.brand}”`,
        detail: `The domain “${registrable}” is a near-miss for “${typo.brandDomain}” (edit distance ${typo.dist} after de-confusing look-alike characters). This is the signature of a typosquatting / impersonation domain.`,
        severity: 'high',
        weight: 58,
        confidence: 0.83,
        evidence: { registrable, resembles: typo.brandDomain, distance: typo.dist },
      });
    }


    const subAndSld = `${td.subdomain ?? ''}`.toLowerCase();
    for (const [brand, dom] of Object.entries(BRANDS)) {
      if (registrable === dom) continue;
      const re = new RegExp(`(^|[.\\-])${brand}([.\\-]|$)`);
      if (re.test(subAndSld) && brand.length >= 4) {
        add({
          id: 'url.brand_in_subdomain',
          category: 'lexical',
          title: `“${brand}” in the sub-domain, but the real site is “${registrable}”`,
          detail: `The name “${brand}” appears in the sub-domain (“${subAndSld}.${registrable}”) to look trustworthy, but the actual registered domain is “${registrable}” - not ${dom}. Browsers only trust the registered domain.`,
          severity: 'high',
          weight: 56,
          confidence: 0.8,
          evidence: { brand, realDomain: registrable, expected: dom },
        });
        break;
      }
    }
  }


  if (tld && SUSPICIOUS_TLDS.has(tld)) {
    add({
      id: 'url.suspicious_tld',
      category: 'lexical',
      title: `Abused top-level domain (.${tld})`,
      detail: `“.${tld}” is heavily over-represented in phishing and malware feeds (often free or near-free to register). Not proof of malice, but a meaningful risk factor.`,
      severity: 'medium',
      weight: 30,
      confidence: 0.7,
      evidence: { tld },
    });
  }


  const subLabels = (td.subdomain ?? '').split('.').filter(Boolean);
  if (!isIpHost && subLabels.length >= 3) {
    const w = Math.min(15 + (subLabels.length - 2) * 8, 38);
    add({
      id: 'url.subdomain_depth',
      category: 'lexical',
      title: `Unusually deep sub-domain (${subLabels.length} levels)`,
      detail: `The host has ${subLabels.length} sub-domain levels (“${td.subdomain}”). Deep, brand-stuffed sub-domains are used to bury the real domain and pad the address bar.`,
      severity: severityForWeight(w),
      weight: w,
      confidence: 0.65,
      evidence: { subdomain: td.subdomain, depth: subLabels.length },
    });
  }


  if (registrable && URL_SHORTENERS.has(registrable)) {
    add({
      id: 'url.shortener',
      category: 'lexical',
      title: 'Link shortener hides the real destination',
      detail: `“${registrable}” is a URL shortener, so the true destination is concealed behind a redirect. Resolve the redirect chain (Argus does this when fetching) before trusting it.`,
      severity: 'low',
      weight: 22,
      confidence: 0.75,
      evidence: { shortener: registrable },
    });
  }


  const kwHits = PHISHING_KEYWORDS.filter(
    (k) => hostForKeywords.includes(k) || fullPath.includes(k),
  );
  if (kwHits.length > 0) {
    const w = Math.min(12 + kwHits.length * 6, 34);
    add({
      id: 'url.keywords',
      category: 'lexical',
      title: `Credential-harvesting keywords (${kwHits.slice(0, 4).join(', ')})`,
      detail: `The URL contains words commonly used to manufacture urgency or imitate a login flow: ${kwHits.join(', ')}. On their own these are weak, but they raise suspicion alongside other signals.`,
      severity: severityForWeight(w),
      weight: w,
      confidence: 0.55,
      evidence: { keywords: kwHits },
    });
  }


  const hyphens = (sld.match(/-/g) ?? []).length;
  if (hyphens >= 2 && !sld.startsWith('xn--')) {
    add({
      id: 'url.hyphenated',
      category: 'lexical',
      title: `Heavily hyphenated domain (${hyphens} hyphens)`,
      detail: `“${registrable}” strings several words together with hyphens - a pattern phishers use to embed brand and action words (e.g. “secure-login-verify”) in a domain they actually control.`,
      severity: 'low',
      weight: 18,
      confidence: 0.6,
      evidence: { sld, hyphens },
    });
  }


  if (url.port && url.port !== '80' && url.port !== '443') {
    add({
      id: 'url.nonstandard_port',
      category: 'lexical',
      title: `Non-standard port (:${url.port})`,
      detail: `The link forces an unusual port (${url.port}) instead of 80/443. Sometimes benign, but also used to reach services on compromised hosts.`,
      severity: 'low',
      weight: 16,
      confidence: 0.6,
      evidence: { port: url.port },
    });
  }


  const lastSeg = url.pathname.split('/').pop() ?? '';
  const ext = lastSeg.includes('.') ? lastSeg.split('.').pop()!.toLowerCase() : '';
  const doubleExt = /\.(pdf|doc|docx|jpg|png|invoice|receipt)\.(\w{2,4})$/i.test(lastSeg);
  if (DANGEROUS_EXTS.has(ext)) {
    add({
      id: 'url.dangerous_ext',
      category: 'lexical',
      title: `Link downloads an executable (.${ext})`,
      detail: `The URL points directly at a “.${ext}” file. Downloading and running executables straight from a link is a primary malware-delivery method.${
        doubleExt ? ' It also uses a deceptive double extension.' : ''
      }`,
      severity: doubleExt ? 'high' : 'medium',
      weight: doubleExt ? 50 : 34,
      confidence: 0.7,
      evidence: { extension: ext, file: lastSeg, doubleExtension: doubleExt },
    });
  }


  for (const [k, v] of url.searchParams) {
    if (REDIRECT_PARAMS.has(k.toLowerCase()) && /^https?:|%2f%2f|\/\//i.test(v)) {
      add({
        id: 'url.open_redirect',
        category: 'lexical',
        title: 'Open-redirect-style parameter',
        detail: `Parameter “${k}” carries another URL (“${v.slice(0, 80)}”). Attackers abuse redirect parameters on trusted domains to bounce victims to hostile pages.`,
        severity: 'medium',
        weight: 26,
        confidence: 0.6,
        evidence: { param: k, value: v.slice(0, 200) },
      });
      break;
    }
  }


  if (rawUrl.length > 120) {
    const w = Math.min(8 + Math.floor((rawUrl.length - 120) / 60) * 4, 20);
    add({
      id: 'url.long',
      category: 'lexical',
      title: `Very long URL (${rawUrl.length} chars)`,
      detail: `Overlong URLs are used to push the real domain out of view and to pack in encoded payloads or tracking. Length alone is weak evidence.`,
      severity: severityForWeight(w),
      weight: w,
      confidence: 0.45,
      evidence: { length: rawUrl.length },
    });
  }


  if (registrable && POPULAR_DOMAINS.has(registrable)) {
    add({
      id: 'url.popular_allowlist',
      category: 'reputation',
      title: `Registered domain is a well-known site (${registrable})`,
      detail: `“${registrable}” is on Argus's curated allowlist of broadly-trusted domains. This dampens weak heuristic signals - but is overridden by any confirmed-malicious finding.`,
      severity: 'info',
      weight: 70,
      confidence: 0.9,
      mitigates: true,
      evidence: { registrable },
    });
  }

  return { parsed, signals };
}
