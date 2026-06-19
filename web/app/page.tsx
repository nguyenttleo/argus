import Dashboard from '@/components/Dashboard';
import { ARGUS_API } from '@/lib/server-api';
import type { Health, ScanSummary, Stats } from '@/lib/types';

export const dynamic = 'force-dynamic';

async function readJson<T>(path: string): Promise<T | null> {
  try {
    const res = await fetch(`${ARGUS_API}${path}`, { cache: 'no-store' });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

export default async function Home() {
  const [health, stats, scanData] = await Promise.all([
    readJson<Health>('/api/health'),
    readJson<Stats>('/api/stats'),
    readJson<{ scans: ScanSummary[] }>('/api/scans?limit=8'),
  ]);

  return <Dashboard initialHealth={health} initialStats={stats} initialScans={scanData?.scans ?? []} />;
}
