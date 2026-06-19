/**
 * Static analysis of fetched page HTML - the kind of inspection urlscan.io does,
 * but performed on bytes Argus already pulled through the SSRF-safe fetcher and
 * NEVER executed. Heuristic regex parsing (no DOM, no JS execution) surfaces the
 * tells of a credential-harvesting page:
 *   - password inputs + where the form actually submits (cross-domain = exfil)
 *   - a known brand named in the page while the domain is something else
 *   - meta-refresh hops, hidden iframes, heavy external script, JS obfuscation.
 */

import { parse as parseDomain } from 'tldts';
import type { ContentInfo, Signal } from '@argus/shared';
import { BRANDS } from './data.ts';

function registrable(url: string, base: string): string | undefined {
  try {
    return parseDomain(new URL(url, base).href).domain ?? undefined;
  } catch {
    return undefined;
  }
}

export function analyzeContent(html: string, baseUrl: string): ContentInfo {
  const lower = html.toLowerCase();
  const baseDomain = registrable(baseUrl, baseUrl);

  const hasPasswordField = /<input\b[^>]*\btype\s*=\s*["']?password\b/i.test(html);

  // form actions
  const formActions: string[] = [];
  let crossDomainForm: string | undefined;
  for (const m of html.matchAll(/<form\b[^>]*>/gi)) {
    const actionAttr = /\baction\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'<>`]+))/i.exec(m[0]);
    const action = (actionAttr?.[1] ?? actionAttr?.[2] ?? actionAttr?.[3] ?? '').trim();
    if (!action || action.startsWith('#') || action.startsWith('javascript:')) continue;
    formActions.push(action);
    const dom = registrable(action, baseUrl);
    if (dom && baseDomain && dom !== baseDomain && /^https?:|^\/\//i.test(action)) {
      crossDomainForm = action;
    }
  }

  // brand names appearing in visible-ish content (title + body text), minus tags
  const text = html.replace(/<script[\s\S]*?<\/script>/gi, ' ').replace(/<style[\s\S]*?<\/style>/gi, ' ').replace(/<[^>]+>/g, ' ').toLowerCase();
  const brandsInContent = Object.keys(BRANDS).filter((b) => b.length >= 4 && new RegExp(`\\b${b}\\b`).test(text));

  const metaRefresh = /<meta\b[^>]*http-equiv\s*=\s*["']?refresh["']?[^>]*content\s*=\s*["'][^"']*url=([^"']+)["']/i.exec(html)?.[1]?.trim();

  const hiddenIframes = [...html.matchAll(/<iframe\b[^>]*>/gi)].filter((m) =>
    /(display\s*:\s*none|visibility\s*:\s*hidden|width\s*=\s*["']?0|height\s*=\s*["']?0|\bhidden\b)/i.test(m[0]),
  ).length;

  let externalScripts = 0;
  for (const m of html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)) {
    const dom = registrable(m[1]!, baseUrl);
    if (dom && baseDomain && dom !== baseDomain) externalScripts++;
  }

  const obfuscation: string[] = [];
  if (/eval\s*\(\s*(atob|unescape|String\.fromCharCode|function)/i.test(html)) obfuscation.push('eval of decoded data');
  if (/document\.write\s*\(\s*unescape/i.test(html)) obfuscation.push('document.write(unescape(...))');
  if (/String\.fromCharCode\s*\(([^)]*,){15,}/i.test(html)) obfuscation.push('long char-code array');
  if (/(atob|unescape)\s*\(\s*["'][A-Za-z0-9+/]{120,}/i.test(html)) obfuscation.push('large encoded blob');
  if (/<script[^>]*>[^<]*\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){20,}/i.test(lower)) obfuscation.push('hex-escaped script');

  const faviconHref = /<link\b[^>]*rel\s*=\s*["'][^"']*icon[^"']*["'][^>]*href\s*=\s*["']([^"']+)["']/i.exec(html)?.[1];
  const title = /<title[^>]*>([\s\S]{0,200}?)<\/title>/i.exec(html)?.[1]?.replace(/\s+/g, ' ').trim();

  return {
    hasPasswordField,
    formActions: formActions.slice(0, 10),
    crossDomainForm,
    brandsInContent,
    metaRefresh,
    hiddenIframes,
    externalScripts,
    obfuscation,
    faviconHref,
    title,
  };
}

export function contentSignals(c: ContentInfo, ctx: { registrableDomain?: string }): Signal[] {
  const out: Signal[] = [];

  if (c.hasPasswordField && c.crossDomainForm) {
    out.push({
      id: 'content.cross_domain_credential_form',
      category: 'content',
      title: 'Password form submits to a different domain',
      detail: `The page has a password field whose form posts to “${c.crossDomainForm}” - a different registered domain than the page itself. This is credential exfiltration: anything typed is sent straight to the attacker.`,
      severity: 'critical',
      weight: 80,
      confidence: 0.8,
      evidence: { action: c.crossDomainForm },
    });
  } else if (c.hasPasswordField) {
    out.push({
      id: 'content.password_field',
      category: 'content',
      title: 'Page collects a password',
      detail:
        'The page contains a password input. Combined with any look-alike or young-domain signals, that is the profile of a credential-harvesting page. Only enter passwords on sites you have verified.',
      severity: 'low',
      weight: 18,
      confidence: 0.55,
    });
  }

  // A brand named on a credential-collection page whose domain is unrelated to that
  // brand. We require the password field: merely *mentioning* a brand (as countless
  // legitimate pages do) is not impersonation - pairing it with a login is.
  if (ctx.registrableDomain && c.hasPasswordField) {
    const ownSld = ctx.registrableDomain.split('.')[0] ?? '';
    const impersonated = c.brandsInContent.filter((b) => !ownSld.includes(b) && !ctx.registrableDomain!.includes(b));
    if (impersonated.length) {
      out.push({
        id: 'content.brand_impersonation',
        category: 'content',
        title: `Login page presents itself as “${impersonated[0]}” but the domain is ${ctx.registrableDomain}`,
        detail: `The page collects credentials and references the brand “${impersonated[0]}”, yet it is served from “${ctx.registrableDomain}”, which is not that brand's domain. A login form on a look-alike domain is the core mechanic of phishing.`,
        severity: 'high',
        weight: 58,
        confidence: 0.65,
        evidence: { brands: impersonated, domain: ctx.registrableDomain },
      });
    }
  }

  if (c.metaRefresh && /^https?:|^\/\//i.test(c.metaRefresh)) {
    out.push({
      id: 'content.meta_refresh',
      category: 'content',
      title: 'Auto-redirect via meta refresh',
      detail: `The page auto-redirects to “${c.metaRefresh.slice(0, 80)}” using a meta-refresh tag, a common cloaking technique to bounce visitors off the landing page.`,
      severity: 'medium',
      weight: 24,
      confidence: 0.6,
    });
  }

  if (c.hiddenIframes > 0) {
    out.push({
      id: 'content.hidden_iframe',
      category: 'content',
      title: `Hidden iframe${c.hiddenIframes > 1 ? `s (${c.hiddenIframes})` : ''}`,
      detail: 'The page embeds hidden/zero-size iframes, often used for drive-by loads, clickjacking or silent third-party content.',
      severity: 'medium',
      weight: 26,
      confidence: 0.6,
    });
  }

  if (c.obfuscation.length) {
    out.push({
      id: 'content.obfuscated_js',
      category: 'content',
      title: `Obfuscated JavaScript (${c.obfuscation.slice(0, 2).join(', ')})`,
      detail: `The page runs obfuscated/encoded JavaScript: ${c.obfuscation.join(', ')}. Legitimate sites rarely need to hide their code this way.`,
      severity: 'medium',
      weight: 30,
      confidence: 0.55,
    });
  }

  return out;
}
