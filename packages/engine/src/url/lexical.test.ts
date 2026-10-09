import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeLexical, levenshtein, skeleton } from './lexical.ts';

function ids(url: string): string[] {
  return analyzeLexical(url).signals.map((s) => s.id);
}

test('levenshtein basic distances', () => {
  assert.equal(levenshtein('paypal', 'paypal'), 0);
  assert.equal(levenshtein('paypa1', 'paypal'), 1);
  assert.equal(levenshtein('g00gle', 'google'), 2);
  assert.equal(levenshtein('', 'abc'), 3);
});

test('skeleton de-confuses look-alike characters', () => {
  assert.equal(skeleton('pаypal'.normalize()), 'paypal');
  assert.equal(skeleton('g00gle'), 'google');
  assert.equal(skeleton('micros0ft'), 'microsoft');
});

test('a clean popular URL yields only the mitigating allowlist signal', () => {
  const { signals } = analyzeLexical('https://www.google.com/search?q=hello');
  const risk = signals.filter((s) => !s.mitigates);
  assert.equal(risk.length, 0, `unexpected risk signals: ${risk.map((s) => s.id).join(',')}`);
  assert.ok(signals.some((s) => s.id === 'url.popular_allowlist' && s.mitigates));
});

test('@-in-url credential trick is flagged high', () => {
  const sigs = analyzeLexical('http://google.com@evil.example.tk/login');
  const s = sigs.signals.find((x) => x.id === 'url.userinfo');
  assert.ok(s);
  assert.equal(s!.severity, 'high');

  assert.equal(sigs.parsed.host, 'evil.example.tk');
});

test('raw IP host is flagged', () => {
  assert.ok(ids('http://185.220.101.5/wp-admin/').includes('url.ip_host'));
});

test('typosquat of paypal is caught', () => {
  const list = ids('http://paypa1.com/login');
  assert.ok(list.includes('url.typosquat'), `got ${list.join(',')}`);
});

test('brand-in-subdomain with foreign registrable domain is caught', () => {
  const list = ids('http://paypal.com.account-verify.tk/');
  assert.ok(list.includes('url.brand_in_subdomain'), `got ${list.join(',')}`);
});

test('suspicious TLD fires', () => {
  assert.ok(ids('http://random-site.tk/').includes('url.suspicious_tld'));
});

test('deep subdomain stacking fires', () => {
  assert.ok(ids('http://login.secure.account.update.example.com/').includes('url.subdomain_depth'));
});

test('url shortener is flagged', () => {
  assert.ok(ids('https://bit.ly/3xYz').includes('url.shortener'));
});

test('dangerous executable extension is flagged', () => {
  assert.ok(ids('http://cdn.example.com/files/invoice.pdf.exe').includes('url.dangerous_ext'));
});

test('open-redirect parameter carrying a URL is flagged', () => {
  assert.ok(ids('https://example.com/out?url=https://evil.tk/x').includes('url.open_redirect'));
});

test('punycode homograph (аpple via Cyrillic) is flagged', () => {

  const list = ids('http://xn--pple-43d.com/');
  assert.ok(list.includes('url.punycode'), `got ${list.join(',')}`);
});

test('a realistic phishing URL scores malicious end-to-end', async () => {
  const { signals } = analyzeLexical('http://paypal.com@secure-paypa1-login.tk/webscr?cmd=update');

  const { scoreSignals } = await import('@argus/shared');
  const r = scoreSignals(signals);
  assert.equal(r.verdict, 'malicious', `score ${r.score}`);
});

test('dangerous schemes (javascript:/data:) are flagged', () => {
  const js = analyzeLexical('javascript:alert(document.cookie)');
  const jsSig = js.signals.find((s) => s.id === 'url.dangerous_scheme');
  assert.ok(jsSig);
  assert.equal(jsSig!.severity, 'high');
  const data = analyzeLexical('data:text/html,<script>alert(1)</script>');
  assert.ok(data.signals.some((s) => s.id === 'url.dangerous_scheme'));
});

test('parsed structure is populated', () => {
  const { parsed } = analyzeLexical('https://a.b.example.co.uk:8443/p?x=1');
  assert.equal(parsed.registrableDomain, 'example.co.uk');
  assert.equal(parsed.publicSuffix, 'co.uk');
  assert.equal(parsed.subdomain, 'a.b');
  assert.equal(parsed.port, 8443);
  assert.equal(parsed.scheme, 'https');
});
