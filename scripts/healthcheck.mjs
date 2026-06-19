const port = process.env.PORT || process.env.WEB_PORT || '3001';
const url = `http://127.0.0.1:${port}/api/health`;

try {
  const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const body = await res.json();
  if (body.status !== 'ok') throw new Error(`unexpected status ${JSON.stringify(body)}`);
  process.exit(0);
} catch (error) {
  console.error(`Healthcheck failed for ${url}:`, error.message);
  process.exit(1);
}
