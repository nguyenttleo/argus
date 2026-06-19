import { proxyJson } from '@/lib/server-api';

export const dynamic = 'force-dynamic';

export async function POST(req: Request): Promise<Response> {
  const body = await req.text();
  return proxyJson('/api/scan/url', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body,
  });
}
