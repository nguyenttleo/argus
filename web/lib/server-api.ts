
export const ARGUS_API = process.env.ARGUS_API ?? 'http://127.0.0.1:8089';

const UNREACHABLE_MESSAGE =
  process.env.NODE_ENV === 'production'
    ? 'Argus analysis service is temporarily unavailable. Please try again shortly.'
    : `Argus API not reachable at ${ARGUS_API}. Is the server running (npm run server)?`;

export async function proxyJson(path: string, init?: RequestInit): Promise<Response> {
  try {
    const res = await fetch(`${ARGUS_API}${path}`, init);
    const text = await res.text();
    const headers = new Headers({ 'content-type': res.headers.get('content-type') ?? 'application/json' });
    for (const key of ['retry-after', 'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset']) {
      const value = res.headers.get(key);
      if (value) headers.set(key, value);
    }
    return new Response(text, {
      status: res.status,
      headers,
    });
  } catch {
    return Response.json(
      { error: 'upstream_unreachable', message: UNREACHABLE_MESSAGE },
      { status: 502 },
    );
  }
}
