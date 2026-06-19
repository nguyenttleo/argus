import { proxyJson } from '@/lib/server-api';

export const dynamic = 'force-dynamic';

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await params;
  return proxyJson(`/api/scan/${encodeURIComponent(id)}`);
}
