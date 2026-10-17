'use client';

import { useCallback, useEffect, useState } from 'react';
import Scanner from '@/components/Scanner';
import ReportCard from '@/components/ReportCard';
import Recent from '@/components/Recent';
import { getHealth, getStats } from '@/lib/api';
import type { Health, Report, ScanSummary, Stats, Verdict } from '@/lib/types';
import { VERDICT } from '@/lib/ui';

function Clock() {
  const [t, setT] = useState('');
  useEffect(() => {
    const tick = () => setT(new Date().toTimeString().slice(0, 8));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);
  return <span className="tabular-nums">{t}</span>;
}

function SectionHead({ label, meta }: { label: string; meta?: string }) {
  return (
    <div className="section-head">
      <span>{label}</span>
      {meta && <span className="text-muted">{meta}</span>}
    </div>
  );
}

function Metric({ label, value, tone }: { label: string; value: React.ReactNode; tone?: string }) {
  return (
    <div className="metric">
      <span className="metric-label">{label}</span>
      <span className="metric-value" style={tone ? { color: tone } : undefined}>
        {value}
      </span>
    </div>
  );
}

function VerdictDistribution({ stats }: { stats: Stats | null }) {
  const total = Math.max(stats?.total ?? 0, 0);
  const pieces: Array<{ key: Verdict; count: number }> = [
    { key: 'malicious', count: stats?.byVerdict.malicious ?? 0 },
    { key: 'suspicious', count: stats?.byVerdict.suspicious ?? 0 },
    { key: 'safe', count: stats?.byVerdict.safe ?? 0 },
  ];

  return (
    <div>
      <div className="distribution" aria-label="verdict distribution">
        {pieces.map((p) => {
          const width = total > 0 ? Math.max(6, (p.count / total) * 100) : 0;
          return p.count > 0 ? <span key={p.key} style={{ width: `${width}%`, background: VERDICT[p.key].hex }} /> : null;
        })}
      </div>
      <div className="mt-2 grid grid-cols-3 gap-2 text-[11px]">
        {pieces.map((p) => (
          <div key={p.key} className="min-w-0">
            <div className="truncate text-muted">{VERDICT[p.key].label.toLowerCase()}</div>
            <div className="tabular-nums" style={{ color: VERDICT[p.key].hex }}>
              {p.count}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function SystemPanel({
  health,
  stats,
  error,
}: {
  health: Health | null;
  stats: Stats | null;
  error: string | null;
}) {
  const providerText = health?.reputationProviders.length ? health.reputationProviders.join(', ') : 'offline/local only';
  const statusTone = error ? '#f92672' : '#a6e22e';

  return (
    <section className="panel p-4">
      <SectionHead label="system" meta={error ? 'attention' : 'online'} />
      <div className="mt-4 grid grid-cols-2 gap-3">
        <Metric label="api" value={error ? 'offline' : health?.status ?? 'checking'} tone={statusTone} />
        <Metric label="rules" value={health?.rulesLoaded ?? '--'} tone="#66d9ef" />
        <Metric label="engine" value={health?.engineVersion ?? '--'} />
        <Metric label="storage" value={health?.quarantine ?? '--'} tone="#e6db74" />
      </div>
      <div className="mt-4 border-t border-border pt-3">
        <div className="text-muted">providers</div>
        <div className="mt-1 break-words text-fg">{providerText}</div>
      </div>
      <div className="mt-4 border-t border-border pt-3">
        <div className="mb-2 flex items-center justify-between">
          <span className="text-muted">scan volume</span>
          <span className="tabular-nums text-fg">{stats?.total ?? 0}</span>
        </div>
        <VerdictDistribution stats={stats} />
      </div>
    </section>
  );
}

export default function Dashboard({
  initialHealth,
  initialStats,
  initialScans,
}: {
  initialHealth: Health | null;
  initialStats: Stats | null;
  initialScans: ScanSummary[];
}) {
  const [report, setReport] = useState<Report | null>(null);
  const [busy, setBusy] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [health, setHealth] = useState<Health | null>(initialHealth);
  const [stats, setStats] = useState<Stats | null>(initialStats);
  const [metaError, setMetaError] = useState<string | null>(initialHealth || initialStats ? null : 'api offline');

  const loadMeta = useCallback(async () => {
    try {
      const [h, s] = await Promise.all([getHealth(), getStats()]);
      setHealth(h);
      setStats(s);
      setMetaError(null);
    } catch {
      setMetaError('api offline');
    }
  }, []);

  useEffect(() => {
    void loadMeta();
    const id = setInterval(loadMeta, 10_000);
    return () => clearInterval(id);
  }, [loadMeta, refreshKey]);

  return (
    <div className="min-h-screen text-[13px]">
      <header className="fixed inset-x-0 top-0 z-50 h-12 border-b border-border bg-surface text-base">
        <div className="mx-auto flex h-full max-w-6xl items-center justify-between px-4">
          <div className="flex min-w-0 items-center gap-3">
            <span className="truncate text-fg">
              <span className="font-bold">argus</span>
              <span className="text-muted"> :: url & file threat scanner</span>
            </span>
          </div>
          <span className="shrink-0 text-muted">
            <Clock />
          </span>
        </div>
      </header>

      <main className="mx-auto grid max-w-6xl grid-cols-[minmax(0,1fr)] gap-5 px-4 pb-16 pt-20 lg:grid-cols-[minmax(0,1fr)_21rem]">
        <section className="min-w-0 space-y-5">
          <section className="panel p-4">
            <SectionHead label="scan" meta={busy ? 'running' : 'ready'} />
            <div className="mt-4">
              <Scanner
                onResult={(r) => {
                  setReport(r);
                  setRefreshKey((k) => k + 1);
                }}
                onBusy={setBusy}
              />
            </div>
          </section>

          <section className={`panel p-4 ${report ? '' : 'panel-muted'}`}>
            <SectionHead label="result" meta={report ? `${report.durationMs}ms / ${report.signals.length} signals` : 'waiting'} />
            <div className="mt-4">
              {report ? (
                <ReportCard report={report} />
              ) : (
                <div className="empty-state">
                  <span className="prompt">&gt;</span>
                  <span>No report selected.</span>
                </div>
              )}
            </div>
          </section>
        </section>

        <aside className="space-y-5 lg:sticky lg:top-20 lg:self-start">
          <SystemPanel health={health} stats={stats} error={metaError} />
          <section className="panel p-4">
            <SectionHead label="recent" meta="latest 8" />
            <div className="mt-4">
              <Recent refreshKey={refreshKey} onSelect={setReport} initialScans={initialScans} />
            </div>
          </section>
        </aside>
      </main>

      <footer className="fixed inset-x-0 bottom-0 z-50 h-7 border-t border-border bg-surface">
        <div className="mx-auto flex h-full max-w-6xl items-center justify-end gap-3 px-2 text-[12px]">
          <span className="shrink-0 text-muted">engine v{health?.engineVersion ?? '1.2.7'}</span>
        </div>
      </footer>
    </div>
  );
}
