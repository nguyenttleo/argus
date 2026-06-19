'use client';

import type { Health, Report, ScanSummary, Stats } from './types';

async function asJson<T>(res: Response): Promise<T> {
  const text = await res.text();
  let data: unknown;
  try {
    data = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`Bad response (${res.status})`);
  }
  if (!res.ok) {
    const msg = (data as { message?: string })?.message ?? `Request failed (${res.status})`;
    throw new Error(msg);
  }
  return data as T;
}

export async function scanUrl(url: string, opts: { fetch?: boolean; reputation?: boolean } = {}): Promise<Report> {
  const res = await fetch('/api/scan/url', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ url, ...opts }),
  });
  return asJson<Report>(res);
}

export async function scanFile(file: File): Promise<Report> {
  const fd = new FormData();
  fd.append('file', file, file.name);
  const res = await fetch('/api/scan/file', { method: 'POST', body: fd });
  return asJson<Report>(res);
}

export async function getScans(limit = 20): Promise<ScanSummary[]> {
  const res = await fetch(`/api/scans?limit=${limit}`, { cache: 'no-store' });
  const data = await asJson<{ scans: ScanSummary[] }>(res);
  return data.scans;
}

export async function getStats(): Promise<Stats> {
  return asJson<Stats>(await fetch('/api/stats', { cache: 'no-store' }));
}

export async function getReport(id: string): Promise<Report> {
  return asJson<Report>(await fetch(`/api/scan/${id}`, { cache: 'no-store' }));
}

export async function getHealth(): Promise<Health> {
  return asJson<Health>(await fetch('/api/health', { cache: 'no-store' }));
}
