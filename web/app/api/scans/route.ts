import { proxyJson } from '@/lib/server-api';

export const dynamic = 'force-dynamic';

export async function GET(req: Request): Promise<Response> {
  const qs = new URL(req.url).searchParams.toString();
  return proxyJson(`/api/scans${qs ? `?${qs}` : ''}`);
}
