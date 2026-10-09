

import type { Report, Severity, Verdict } from '@argus/shared';

const C = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m',
  gray: '\x1b[90m',
  bgRed: '\x1b[41m',
  bgYellow: '\x1b[43m',
  bgGreen: '\x1b[42m',
  black: '\x1b[30m',
};

function paint(color: boolean, codes: string, s: string): string {
  return color ? `${codes}${s}${C.reset}` : s;
}

const VERDICT_BADGE: Record<Verdict, { label: string; bg: string }> = {
  safe: { label: ' SAFE ', bg: C.bgGreen + C.black },
  suspicious: { label: ' SUSPICIOUS ', bg: C.bgYellow + C.black },
  malicious: { label: ' MALICIOUS ', bg: C.bgRed + C.bold },
};

const SEV_COLOR: Record<Severity, string> = {
  critical: C.red + C.bold,
  high: C.magenta,
  medium: C.yellow,
  low: C.cyan,
  info: C.gray,
};

const SEV_DOT: Record<Severity, string> = {
  critical: '●',
  high: '●',
  medium: '◆',
  low: '▲',
  info: '·',
};

function bar(score: number, color: boolean): string {
  const width = 24;
  const filled = Math.round((score / 100) * width);
  const col = score >= 60 ? C.red : score >= 25 ? C.yellow : C.green;
  const full = '█'.repeat(filled);
  const empty = '░'.repeat(width - filled);
  return paint(color, col, full) + paint(color, C.gray, empty);
}

export function renderReport(report: Report, opts: { color?: boolean } = {}): string {
  const color = opts.color ?? false;
  const out: string[] = [];
  const badge = VERDICT_BADGE[report.verdict];

  out.push('');
  out.push(`  ${paint(color, C.bold + C.cyan, 'ARGUS')} ${paint(color, C.gray, '▸')} ${report.target}`);
  out.push('');
  out.push(
    `  ${paint(color, badge.bg, badge.label)}   ${bar(report.score, color)}  ${paint(color, C.bold, `${report.score}/100`)} ${paint(color, C.gray, `· confidence ${(report.confidence * 100).toFixed(0)}%`)}`,
  );
  out.push('');
  out.push(`  ${wrap(report.summary, 76, '  ')}`);
  out.push('');

  const risk = report.signals.filter((s) => !s.mitigates && s.weight > 0);
  const mit = report.signals.filter((s) => s.mitigates);
  const info = report.signals.filter((s) => !s.mitigates && s.weight === 0);

  if (risk.length) {
    out.push(`  ${paint(color, C.bold, `Risk signals (${risk.length})`)}`);
    for (const s of risk) {
      const dot = paint(color, SEV_COLOR[s.severity], SEV_DOT[s.severity]);
      const tag = paint(color, SEV_COLOR[s.severity], `[${s.severity}]`);
      out.push(`   ${dot} ${tag} ${paint(color, C.bold, s.title)}`);
      out.push(`     ${paint(color, C.gray, wrap(s.detail, 72, '     '))}`);
    }
    out.push('');
  }

  if (mit.length) {
    out.push(`  ${paint(color, C.green, 'Mitigating')}`);
    for (const s of mit) out.push(`   ${paint(color, C.green, '✓')} ${s.title}`);
    out.push('');
  }

  if (info.length) {
    for (const s of info) out.push(`  ${paint(color, C.gray, `ℹ ${s.title}`)}`);
    if (info.length) out.push('');
  }


  if (report.detail.kind === 'url') {
    const d = report.detail;
    const facts: string[] = [];
    if (d.registrableDomain) facts.push(`domain ${d.registrableDomain}`);
    if (d.resolvedIps.length) facts.push(`ip ${d.resolvedIps.join(', ')}`);
    if (d.finalUrl && d.finalUrl !== d.normalized) facts.push(`final ${d.finalUrl}`);
    if (d.redirects.length) facts.push(`${d.redirects.length} redirect(s)`);
    if (d.tls) facts.push(`tls ${d.tls.valid ? 'valid' : 'INVALID'}${d.tls.issuer ? ` (${d.tls.issuer})` : ''}`);
    if (facts.length) out.push(`  ${paint(color, C.gray, facts.join(' · '))}`);
  } else {
    const d = report.detail;
    const facts = [`sha256 ${d.sha256.slice(0, 32)}…`, `${d.size} bytes`, `type ${d.realTypeLabel ?? d.realType ?? 'unknown'}`, `entropy ${d.entropy}`];
    out.push(`  ${paint(color, C.gray, facts.join(' · '))}`);
    if (d.yaraHits.length) out.push(`  ${paint(color, C.gray, `yara: ${d.yaraHits.map((h) => h.rule).join(', ')}`)}`);
  }

  if (report.iocs.length) {
    const shown = report.iocs.slice(0, 6).map((i) => `${i.type}:${i.value}`);
    out.push(`  ${paint(color, C.gray, `IOCs: ${shown.join('  ')}${report.iocs.length > 6 ? ` (+${report.iocs.length - 6})` : ''}`)}`);
  }
  out.push('');
  out.push(`  ${paint(color, C.gray, `scanned in ${report.durationMs}ms · engine v${report.engineVersion}`)}`);
  out.push('');
  return out.join('\n');
}

function wrap(text: string, width: number, indent: string): string {
  const words = text.split(/\s+/);
  const lines: string[] = [];
  let line = '';
  for (const w of words) {
    if (line.length + w.length + 1 > width) {
      lines.push(line);
      line = w;
    } else {
      line = line ? `${line} ${w}` : w;
    }
  }
  if (line) lines.push(line);
  return lines.join('\n' + indent);
}


export function exitCodeFor(verdict: Verdict): number {
  return verdict === 'malicious' ? 2 : verdict === 'suspicious' ? 1 : 0;
}
