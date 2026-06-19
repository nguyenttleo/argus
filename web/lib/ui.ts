import type { Severity, Verdict } from './types';

export const VERDICT: Record<Verdict, { label: string; hex: string }> = {
  safe: { label: 'SAFE', hex: '#a6e22e' },
  suspicious: { label: 'SUSPICIOUS', hex: '#fd971f' },
  malicious: { label: 'MALICIOUS', hex: '#f92672' },
};

export const SEVERITY: Record<Severity, { mark: string; hex: string }> = {
  critical: { mark: '!', hex: '#f92672' },
  high: { mark: '!', hex: '#f92672' },
  medium: { mark: '*', hex: '#fd971f' },
  low: { mark: '+', hex: '#66d9ef' },
  info: { mark: '.', hex: '#75715e' },
};

export function timeAgo(iso: string): string {
  const then = new Date(iso).getTime();
  const s = Math.max(0, Math.floor((Date.now() - then) / 1000));
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m`;
  if (s < 86400) return `${Math.floor(s / 3600)}h`;
  return `${Math.floor(s / 86400)}d`;
}

export function truncate(s: string, n: number): string {
  return s.length > n ? s.slice(0, Math.max(0, n - 3)) + '...' : s;
}

export function bar(score: number, width = 22): { filled: string; empty: string } {
  const f = Math.round((score / 100) * width);
  return { filled: '#'.repeat(f), empty: '-'.repeat(width - f) };
}
