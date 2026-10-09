'use client';

import { useCallback, useEffect, useState } from 'react';
import { getReport, getScans } from '@/lib/api';
import type { Report, ScanSummary } from '@/lib/types';
import { VERDICT, timeAgo, truncate } from '@/lib/ui';

export default function Recent({
  refreshKey,
  onSelect,
  initialScans = [],
}: {
  refreshKey: number;
  onSelect: (r: Report) => void;
  initialScans?: ScanSummary[];
}) {
  const [scans, setScans] = useState<ScanSummary[]>(initialScans);
  const [loadingId, setLoadingId] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setScans(await getScans(8));
    } catch {}
  }, []);

  useEffect(() => {
    void load();
  }, [load, refreshKey]);

  if (scans.length === 0) {
    return <div className="text-muted">No scans yet.</div>;
  }

  return (
    <div className="text-[13px]">
      <div className="recent-head">
        <span>verdict</span>
        <span>kind</span>
        <span>score</span>
        <span>target</span>
        <span>age</span>
      </div>
      <div className="mt-1">
        {scans.map((s) => {
          const v = VERDICT[s.verdict];
          return (
            <button
              key={s.id}
              onClick={async () => {
                try {
                  setLoadingId(s.id);
                  onSelect(await getReport(s.id));
                } catch {} finally {
                  setLoadingId(null);
                }
              }}
              className="row recent-row"
            >
              <span style={{ color: v.hex }}>{v.label.toLowerCase()}</span>
              <span className="text-muted">{s.kind}</span>
              <span className="text-right tabular-nums text-muted">{s.score}</span>
              <span className="min-w-0 truncate text-fg/90">{loadingId === s.id ? 'loading...' : truncate(s.target, 46)}</span>
              <span className="text-right tabular-nums text-muted">{timeAgo(s.createdAt)}</span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
