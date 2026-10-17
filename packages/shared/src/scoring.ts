import type { Report, Severity, Signal, Verdict } from './types.ts';
import { SEVERITY_RANK } from './types.ts';

export const THRESHOLD_SUSPICIOUS = 25;
export const THRESHOLD_MALICIOUS = 60;

const DECISIVE_CONFIDENCE = 0.85;

const DECISIVE_FLOOR = 0.92;

export interface ScoreResult {
  score: number;
  verdict: Verdict;
  confidence: number;

  decisive: boolean;
}

function clamp01(x: number): number {
  if (Number.isNaN(x)) return 0;
  return x < 0 ? 0 : x > 1 ? 1 : x;
}

export function signalProbability(s: Signal): number {
  return clamp01((s.weight / 100) * s.confidence);
}

function noisyOr(probs: number[]): number {
  return 1 - probs.reduce((acc, p) => acc * (1 - p), 1);
}

export function scoreSignals(signals: Signal[]): ScoreResult {
  const risk = signals.filter((s) => !s.mitigates && s.weight > 0);
  const mit = signals.filter((s) => s.mitigates && s.weight > 0);

  const decisiveSignals = risk.filter(
    (s) => s.severity === 'critical' && s.confidence >= DECISIVE_CONFIDENCE,
  );
  const decisive = decisiveSignals.length > 0;

  const riskP = noisyOr(risk.map(signalProbability));
  const mitP = mit.reduce((acc, s) => acc * (1 - signalProbability(s)), 1);

  const finalP = decisive ? Math.max(riskP, DECISIVE_FLOOR) : riskP * mitP;
  const score = Math.round(clamp01(finalP) * 100);

  const verdict: Verdict =
    score >= THRESHOLD_MALICIOUS
      ? 'malicious'
      : score >= THRESHOLD_SUSPICIOUS
        ? 'suspicious'
        : 'safe';

  return { score, verdict, confidence: verdictConfidence(signals, score, decisive), decisive };
}

function verdictConfidence(signals: Signal[], score: number, decisive: boolean): number {
  if (decisive) return 0.97;
  const scoring = signals.filter((s) => s.weight > 0);
  if (scoring.length === 0) return 0.55;

  const avgConf = scoring.reduce((a, s) => a + s.confidence, 0) / scoring.length;
  const corroboration = Math.min(scoring.length, 6) / 6;

  const distToBoundary = Math.min(
    Math.abs(score - THRESHOLD_SUSPICIOUS),
    Math.abs(score - THRESHOLD_MALICIOUS),
  );
  const boundaryClarity = clamp01(distToBoundary / 25);

  const c = 0.45 + 0.2 * corroboration + 0.2 * (avgConf - 0.5) + 0.2 * boundaryClarity;
  return clamp01(c);
}

export const VERDICT_LABEL: Record<Verdict, string> = {
  safe: 'Safe',
  suspicious: 'Suspicious',
  malicious: 'Malicious',
};

export function sortSignalsForDisplay(signals: Signal[]): Signal[] {
  return [...signals].sort((a, b) => {
    const sev = SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    if (sev !== 0) return sev;
    return b.weight - a.weight;
  });
}

export function summarize(kind: 'url' | 'file', result: ScoreResult, signals: Signal[]): string {
  const risk = sortSignalsForDisplay(signals.filter((s) => !s.mitigates && s.weight > 0));
  const subject = kind === 'url' ? 'This link' : 'This file';
  const topReasons = risk.slice(0, 2).map((s) => s.title.toLowerCase());

  if (result.verdict === 'malicious') {
    const lead = result.decisive ? 'matched a known threat signature' : 'shows strong signs of being malicious';
    return `${subject} ${lead}${topReasons.length ? ` - ${topReasons.join('; ')}.` : '.'} Do not open or trust it.`;
  }
  if (result.verdict === 'suspicious') {
    return `${subject} has some risk indicators${topReasons.length ? ` - ${topReasons.join('; ')}` : ''}. Treat it with caution.`;
  }
  if (risk.length === 0) {
    return `${subject} showed no risk indicators in the checks we ran. Stay alert anyway.`;
  }
  return `${subject} looks low-risk, with only minor indicators. No strong threat signals found.`;
}

export function buildReport(input: {
  id: string;
  kind: 'url' | 'file';
  target: string;
  signals: Signal[];
  iocs: Report['iocs'];
  detail: Report['detail'];
  createdAt: string;
  durationMs: number;
  engineVersion: string;
}): Report {
  const score = scoreSignals(input.signals);
  return {
    id: input.id,
    kind: input.kind,
    target: input.target,
    verdict: score.verdict,
    score: score.score,
    confidence: score.confidence,
    summary: summarize(input.kind, score, input.signals),
    signals: sortSignalsForDisplay(input.signals),
    iocs: input.iocs,
    detail: input.detail,
    createdAt: input.createdAt,
    engineVersion: input.engineVersion,
    durationMs: input.durationMs,
  };
}

export function signal(
  s: Omit<Signal, 'confidence'> & { confidence?: number },
): Signal {
  return { confidence: 0.8, ...s };
}

export function severityForWeight(weight: number): Severity {
  if (weight >= 80) return 'critical';
  if (weight >= 50) return 'high';
  if (weight >= 30) return 'medium';
  if (weight >= 15) return 'low';
  return 'info';
}
