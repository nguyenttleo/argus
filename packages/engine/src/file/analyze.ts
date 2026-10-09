

import { randomUUID } from 'node:crypto';
import {
  buildReport,
  ENGINE_VERSION,
  type DetonationResult,
  type FileScanDetail,
  type FileScanOptions,
  type Ioc,
  type ReputationResult,
  type Severity,
  type Signal,
} from '@argus/shared';
import { loadConfig, type EngineConfig } from '../config.ts';
import { createReputationRegistry, type ReputationRegistry } from '../reputation/registry.ts';
import { localFeedProvider } from '../reputation/localfeed.ts';
import { hashBytes, shannonEntropy } from './hash.ts';
import { checkTypeMismatch, detectType } from './magic.ts';
import { scanBytes, type YaraRule } from './yara.ts';
import { loadBuiltinRules } from './rules.ts';
import { analyzeStatic } from './static.ts';
import { tartarusDetonate } from './detonate.ts';

export interface AnalyzeFileInput {
  filename: string;
  bytes: Uint8Array;

  declaredType?: string;
}

export type DetonateFn = (
  bytes: Uint8Array,
  filename: string,
  config: EngineConfig,
) => Promise<DetonationResult>;

export interface AnalyzeFileDeps {
  config?: EngineConfig;
  registry?: ReputationRegistry;
  rules?: YaraRule[];
  detonate?: DetonateFn;
  now?: () => Date;
  idGen?: () => string;
}

const HIGH_ENTROPY = 7.2;
const NATURALLY_HIGH_ENTROPY = new Set(['archive', 'image', 'media']);

function defaultWeight(sev: Severity): number {
  return sev === 'critical' ? 90 : sev === 'high' ? 58 : sev === 'medium' ? 32 : sev === 'low' ? 16 : 5;
}

export async function analyzeFile(
  input: AnalyzeFileInput,
  options: FileScanOptions = {},
  deps: AnalyzeFileDeps = {},
): Promise<ReturnType<typeof buildReport>> {
  const start = performance.now();
  const config = deps.config ?? loadConfig();
  const now = deps.now ?? (() => new Date());
  const idGen = deps.idGen ?? (() => randomUUID());
  const bytes = input.bytes instanceof Uint8Array ? input.bytes : new Uint8Array(input.bytes);

  const { sha256, sha1, md5 } = hashBytes(bytes);
  const entropy = shannonEntropy(bytes);
  const detected = detectType(bytes);
  const mismatch = checkTypeMismatch(bytes, input.filename);

  const signals: Signal[] = [];
  const iocs: Ioc[] = [{ type: 'sha256', value: sha256 }];

  const detail: FileScanDetail = {
    kind: 'file',
    filename: input.filename,
    size: bytes.length,
    sha256,
    sha1,
    md5,
    declaredType: input.declaredType ?? extLabel(input.filename),
    realType: detected?.type,
    realTypeLabel: detected?.label,
    typeMismatch: mismatch.mismatch,
    entropy: Number(entropy.toFixed(3)),
    staticFindings: [],
    yaraHits: [],
  };

  if (bytes.length === 0) {
    signals.push({
      id: 'meta.empty',
      category: 'meta',
      title: 'Empty file',
      detail: 'The file has no content to analyze.',
      severity: 'info',
      weight: 0,
      confidence: 0.6,
    });
  }


  if (mismatch.executableMasquerade) {
    signals.push({
      id: 'file.exe_masquerade',
      category: 'static',
      title: `Executable disguised as ".${mismatch.declaredExt}"`,
      detail: `The filename claims a ".${mismatch.declaredExt}" file, but the bytes are actually ${detected?.label}. Disguising an executable as a document/image is a hallmark of malware delivery.`,
      severity: 'high',
      weight: 68,
      confidence: 0.9,
      evidence: { declaredExt: mismatch.declaredExt, realType: detected?.type },
    });
  } else if (mismatch.mismatch && detected) {
    signals.push({
      id: 'file.type_mismatch',
      category: 'static',
      title: `Content doesn't match the ".${mismatch.declaredExt}" extension`,
      detail: `The extension suggests ".${mismatch.declaredExt}" but the bytes are ${detected.label}. Not always malicious, but worth noting.`,
      severity: 'medium',
      weight: 30,
      confidence: 0.75,
      evidence: { declaredExt: mismatch.declaredExt, realType: detected.type },
    });
  }


  if (entropy > HIGH_ENTROPY && !(detected && NATURALLY_HIGH_ENTROPY.has(detected.family)) && bytes.length > 256) {
    signals.push({
      id: 'file.high_entropy',
      category: 'static',
      title: `High entropy (${entropy.toFixed(2)}/8) - possibly packed/encrypted`,
      detail: `The byte distribution is near-random (${entropy.toFixed(2)} bits/byte). For a non-compressed file type this suggests packing or encryption used to hide content from scanners.`,
      severity: 'low',
      weight: 22,
      confidence: 0.55,
      evidence: { entropy },
    });
  }


  const rules = deps.rules ?? loadBuiltinRules().rules;
  const yaraMatches = scanBytes(bytes, rules);
  detail.yaraHits = yaraMatches.map((m) => ({
    rule: m.rule,
    tags: m.tags,
    meta: Object.fromEntries(Object.entries(m.meta).map(([k, v]) => [k, String(v)])),
    strings: m.strings,
  }));
  for (const m of yaraMatches) {
    const sev = (typeof m.meta.severity === 'string' ? m.meta.severity : 'high') as Severity;
    const weight = typeof m.meta.weight === 'number' ? m.meta.weight : defaultWeight(sev);
    const desc = typeof m.meta.description === 'string' ? m.meta.description : `matched rule ${m.rule}`;
    signals.push({
      id: `yara.${m.rule}`,
      category: 'yara',
      title: `YARA: ${m.rule}`,
      detail: `${desc}${m.strings.length ? ` (matched ${m.strings.join(', ')})` : ''}.`,
      severity: sev,
      weight,
      confidence: sev === 'critical' ? 0.92 : sev === 'high' ? 0.82 : 0.7,
      evidence: { rule: m.rule, tags: m.tags, strings: m.strings },
    });
  }


  const stat = analyzeStatic(bytes, input.filename, detected);
  detail.staticFindings = stat.findings;
  if (stat.pe) {
    detail.pe = stat.pe;
    if (stat.pe.imphash) iocs.push({ type: 'md5', value: stat.pe.imphash, note: 'imphash' });
  }
  signals.push(...stat.signals);
  for (const ic of stat.iocs) iocs.push(ic);


  let repResults: ReputationResult[];
  if (options.reputation) {
    const registry = deps.registry ?? createReputationRegistry(config);
    repResults = await registry.checkHash(sha256);
  } else {
    repResults = [await localFeedProvider().checkHash!(sha256, new AbortController().signal)];
  }
  const vt = repResults.find((r) => r.provider === 'VirusTotal');
  if (vt) detail.vt = vt;
  const mb = repResults.find((r) => r.provider === 'MalwareBazaar');
  if (mb) detail.mbazaar = mb;
  for (const r of repResults) {
    if (r.available && r.listed) {
      const decisive = r.provider === 'VirusTotal' || r.provider === 'MalwareBazaar';
      signals.push({
        id: `rep.${r.provider.toLowerCase().replace(/[^a-z]+/g, '_')}`,
        category: 'reputation',
        title: `Flagged by ${r.provider}`,
        detail: `${r.provider}: ${r.detail ?? 'known-bad hash'}${r.categories?.length ? ` (${r.categories.join(', ')})` : ''}.`,
        severity: decisive ? 'critical' : 'high',
        weight: decisive ? 95 : 75,
        confidence: decisive ? 0.95 : 0.85,
        evidence: { provider: r.provider, source: r.source },
      });
    }
  }
  if (options.reputation && !repResults.some((r) => r.available && r.provider !== 'Local sample feed')) {
    signals.push({
      id: 'meta.reputation_unavailable',
      category: 'meta',
      title: 'External reputation unavailable',
      detail: 'VirusTotal was not consulted (no API key or offline). Verdict relies on signatures, YARA and static analysis.',
      severity: 'info',
      weight: 0,
      confidence: 0.5,
    });
  }


  const detonateFn = deps.detonate ?? tartarusDetonate;
  if (options.detonate && config.tartarusUrl) {
    try {
      const det = await detonateFn(bytes, input.filename, config);
      detail.detonation = det;
      if (det.ran && det.iocs?.length) {
        for (const ic of det.iocs) iocs.push(ic);
        signals.push({
          id: 'detonation.behavioral_iocs',
          category: 'detonation',
          title: `Sandbox observed ${det.iocs.length} behavioural IOC(s)`,
          detail: `Detonated in Tartarus: ${det.detail ?? 'behavioural indicators captured'}.`,
          severity: 'high',
          weight: 60,
          confidence: 0.8,
          evidence: { iocs: det.iocs },
        });
      }
    } catch (e) {
      detail.detonation = { available: false, ran: false, detail: `detonation failed: ${(e as Error).message}`, source: 'unavailable' };
    }
  }

  const shortSha = sha256.slice(0, 12);
  return buildReport({
    id: idGen(),
    kind: 'file',
    target: `${input.filename} (${shortSha})`,
    signals,
    iocs,
    detail,
    createdAt: now().toISOString(),
    durationMs: Math.round(performance.now() - start),
    engineVersion: ENGINE_VERSION,
  });
}

function extLabel(filename: string): string | undefined {
  const dot = filename.lastIndexOf('.');
  return dot > 0 ? filename.slice(dot + 1).toLowerCase() : undefined;
}
