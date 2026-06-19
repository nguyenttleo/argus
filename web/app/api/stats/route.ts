import { proxyJson } from '@/lib/server-api';

export const dynamic = 'force-dynamic';

export async function GET(): Promise<Response> {
  return proxyJson('/api/stats');
}
