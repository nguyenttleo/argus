import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  scoreSignals,
  signalProbability,
  summarize,
  sortSignalsForDisplay,
  THRESHOLD_MALICIOUS,
  THRESHOLD_SUSPICIOUS,
} from './scoring.ts';
import type { Signal } from './types.ts';

function sig(p: Partial<Signal>): Signal {
  return {
    id: 'x',
    category: 'lexical',
    title: 't',
    detail: 'd',
    severity: 'medium',
    weight: 30,
    confidence: 0.8,
    ...p,
  };
}

test('no signals ⇒ safe with zero score', () => {
  const r = scoreSignals([]);
  assert.equal(r.score, 0);
  assert.equal(r.verdict, 'safe');
  assert.equal(r.decisive, false);
});

test('a single decisive critical signal forces malicious regardless of weight math', () => {
  const r = scoreSignals([sig({ severity: 'critical', weight: 100, confidence: 0.98, id: 'file.eicar' })]);
  assert.equal(r.verdict, 'malicious');
  assert.ok(r.score >= 92, `expected >=92, got ${r.score}`);
  assert.equal(r.decisive, true);
  assert.ok(r.confidence >= 0.95);
});

test('noisy-OR has diminishing returns - many weak signals do not trivially max out', () => {
  const weak = Array.from({ length: 10 }, (_, i) => sig({ id: `w${i}`, weight: 10, confidence: 0.5, severity: 'low' }));
  const r = scoreSignals(weak);
  // 10 × p=0.05 ⇒ 1-(0.95^10) ≈ 0.40 ⇒ ~40, suspicious - not malicious.
  assert.ok(r.score < THRESHOLD_MALICIOUS, `expected < ${THRESHOLD_MALICIOUS}, got ${r.score}`);
  assert.ok(r.score >= THRESHOLD_SUSPICIOUS, `expected >= ${THRESHOLD_SUSPICIOUS}, got ${r.score}`);
  assert.equal(r.verdict, 'suspicious');
});

test('order independence', () => {
  const a = sig({ id: 'a', weight: 40, confidence: 0.7 });
  const b = sig({ id: 'b', weight: 55, confidence: 0.9, severity: 'high' });
  const c = sig({ id: 'c', weight: 20, confidence: 0.6, severity: 'low' });
  const r1 = scoreSignals([a, b, c]);
  const r2 = scoreSignals([c, a, b]);
  assert.equal(r1.score, r2.score);
  assert.equal(r1.verdict, r2.verdict);
});

test('mitigating evidence dampens a non-decisive score', () => {
  const risky = [sig({ id: 'r1', weight: 45, confidence: 0.8, severity: 'medium' })];
  const withMit = [
    ...risky,
    sig({ id: 'm1', weight: 60, confidence: 0.9, mitigates: true, severity: 'info' }),
  ];
  const base = scoreSignals(risky);
  const damped = scoreSignals(withMit);
  assert.ok(damped.score < base.score, `mitigation should lower score: ${damped.score} !< ${base.score}`);
});

test('mitigation can NEVER pull a decisive malicious verdict down', () => {
  const signals = [
    sig({ id: 'file.eicar', severity: 'critical', weight: 100, confidence: 0.98 }),
    sig({ id: 'm.popular', weight: 95, confidence: 0.99, mitigates: true, severity: 'info' }),
  ];
  const r = scoreSignals(signals);
  assert.equal(r.verdict, 'malicious');
  assert.ok(r.score >= 92);
});

test('probability is clamped and weight/confidence scaled', () => {
  assert.equal(signalProbability(sig({ weight: 100, confidence: 1 })), 1);
  assert.equal(signalProbability(sig({ weight: 0, confidence: 1 })), 0);
  assert.equal(signalProbability(sig({ weight: 50, confidence: 0.5 })), 0.25);
});

test('verdict confidence is lower near a boundary than far from it', () => {
  // Construct a score hugging the malicious boundary vs one far above.
  const near = scoreSignals([sig({ weight: 62, confidence: 0.97, severity: 'high' })]);
  const far = scoreSignals([sig({ weight: 98, confidence: 0.97, severity: 'high' })]);
  assert.ok(far.confidence > near.confidence);
});

test('summary text matches verdict tone', () => {
  const mal = scoreSignals([sig({ severity: 'critical', weight: 100, confidence: 0.98, title: 'Known malware signature' })]);
  const text = summarize('file', mal, [sig({ severity: 'critical', weight: 100, confidence: 0.98, title: 'Known malware signature' })]);
  assert.match(text, /Do not open/);
});

test('display sort puts critical/high-weight first', () => {
  const sorted = sortSignalsForDisplay([
    sig({ id: 'low', severity: 'low', weight: 10 }),
    sig({ id: 'crit', severity: 'critical', weight: 90 }),
    sig({ id: 'med', severity: 'medium', weight: 40 }),
  ]);
  assert.equal(sorted[0]?.id, 'crit');
  assert.equal(sorted[2]?.id, 'low');
});
