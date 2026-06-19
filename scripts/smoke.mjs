const baseUrl = (process.env.ARGUS_PUBLIC_URL || process.env.PUBLIC_URL || 'http://localhost:3001').replace(/\/$/, '');

async function readJson(path, init) {
  const res = await fetch(`${baseUrl}${path}`, init);
  const text = await res.text();
  let body;
  try {
    body = text ? JSON.parse(text.replace(/^\uFEFF/, '')) : {};
  } catch {
    throw new Error(`${path} returned non-JSON (${res.status}): ${text.slice(0, 120)}`);
  }
  if (!res.ok) {
    throw new Error(`${path} failed (${res.status}): ${body.message ?? body.error ?? text}`);
  }
  return body;
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const health = await readJson('/api/health');
assert(health.status === 'ok', `expected healthy API, got ${JSON.stringify(health)}`);

const stats = await readJson('/api/stats');
assert(typeof stats.total === 'number', 'expected stats.total to be a number');

const safe = await readJson('/api/scan/url', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ url: 'https://www.google.com/', fetch: false, reputation: true }),
});
assert(safe.verdict === 'safe', `expected google.com to be safe, got ${safe.verdict}`);

const malicious = await readJson('/api/scan/url', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ url: 'http://paypal.com@secure-paypa1-login.tk/webscr?cmd=verify', fetch: false, reputation: true }),
});
assert(malicious.verdict === 'malicious', `expected phishing sample to be malicious, got ${malicious.verdict}`);

const form = new FormData();
form.append('file', new File(['hello from argus smoke test'], 'smoke.txt', { type: 'text/plain' }));
const file = await readJson('/api/scan/file', { method: 'POST', body: form });
assert(file.kind === 'file' && file.verdict === 'safe', `expected smoke file to scan safely, got ${file.verdict}`);

console.log(
  JSON.stringify(
    {
      ok: true,
      baseUrl,
      health: health.status,
      rulesLoaded: health.rulesLoaded,
      statsTotal: stats.total,
      urlScan: safe.verdict,
      phishingScan: malicious.verdict,
      fileScan: file.verdict,
    },
    null,
    2,
  ),
);
