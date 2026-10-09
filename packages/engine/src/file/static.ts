

import type { Ioc, PeDetail, Signal, StaticFinding } from '@argus/shared';
import type { DetectedType } from './magic.ts';
import { parsePeDetail } from './pe.ts';

export interface StaticResult {
  findings: StaticFinding[];
  signals: Signal[];
  iocs: Ioc[];
  pe?: PeDetail;
  archive?: ArchiveInfo;
}

export interface ArchiveInfo {
  entries: number;
  totalCompressed: number;
  totalUncompressed: number;
  ratio: number;
  names: string[];
}

function u16(buf: Uint8Array, off: number): number {
  if (off + 2 > buf.length) return 0;
  return buf[off]! | (buf[off + 1]! << 8);
}
function u32(buf: Uint8Array, off: number): number {
  if (off + 4 > buf.length) return 0;
  return (buf[off]! | (buf[off + 1]! << 8) | (buf[off + 2]! << 16) | (buf[off + 3]! << 24)) >>> 0;
}



const EOCD_SIG = 0x06054b50;
const CDIR_SIG = 0x02014b50;

export function parseZip(buf: Uint8Array): ArchiveInfo | undefined {

  const minPos = Math.max(0, buf.length - (0xffff + 22));
  let eocd = -1;
  for (let i = buf.length - 22; i >= minPos; i--) {
    if (u32(buf, i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) return undefined;
  const entries = u16(buf, eocd + 10);
  let cd = u32(buf, eocd + 16);
  const names: string[] = [];
  let totalCompressed = 0;
  let totalUncompressed = 0;
  let count = 0;
  while (cd + 46 <= buf.length && u32(buf, cd) === CDIR_SIG && count < 100_000) {
    const comp = u32(buf, cd + 20);
    const uncomp = u32(buf, cd + 24);
    const nameLen = u16(buf, cd + 28);
    const extraLen = u16(buf, cd + 30);
    const commentLen = u16(buf, cd + 32);
    const name = Buffer.from(buf.subarray(cd + 46, cd + 46 + nameLen)).toString('utf8');
    if (names.length < 200) names.push(name);
    totalCompressed += comp;
    totalUncompressed += uncomp;
    count++;
    cd += 46 + nameLen + extraLen + commentLen;
  }
  const ratio = totalCompressed > 0 ? totalUncompressed / totalCompressed : 0;
  return { entries: entries || count, totalCompressed, totalUncompressed, ratio, names };
}



function latin1(buf: Uint8Array, max = 5_000_000): string {
  return Buffer.from(buf.subarray(0, max)).toString('latin1');
}

function finding(
  findings: StaticFinding[],
  signals: Signal[],
  f: StaticFinding & { weight: number; confidence?: number; category?: Signal['category'] },
): void {
  findings.push({ id: f.id, title: f.title, detail: f.detail, severity: f.severity });
  signals.push({
    id: `static.${f.id}`,
    category: f.category ?? 'static',
    title: f.title,
    detail: f.detail,
    severity: f.severity,
    weight: f.weight,
    confidence: f.confidence ?? 0.75,
  });
}



export function analyzeStatic(buf: Uint8Array, filename: string, detected?: DetectedType): StaticResult {
  const findings: StaticFinding[] = [];
  const signals: Signal[] = [];
  const iocs: Ioc[] = [];
  const result: StaticResult = { findings, signals, iocs };
  const text = latin1(buf);


  if (detected?.type === 'zip') {
    const arc = parseZip(buf);
    if (arc) {
      result.archive = arc;
      const hasMacro = arc.names.some((n) => /vbaproject\.bin$/i.test(n) || /\/vbaData\.xml$/i.test(n));
      if (hasMacro) {
        finding(findings, signals, {
          id: 'ooxml_macro',
          title: 'Office document contains a VBA macro project',
          detail: `The archive includes "${arc.names.find((n) => /vbaproject\.bin$/i.test(n))}". Macro-enabled documents are a leading malware-delivery vector; only enable macros from sources you fully trust.`,
          severity: 'high',
          weight: 55,
          confidence: 0.85,
        });
      }
      const nested = arc.names.filter((n) => /\.(zip|rar|7z|gz|cab|iso|img)$/i.test(n));
      if (arc.ratio > 100 && arc.totalUncompressed > 50 * 1024 * 1024) {
        finding(findings, signals, {
          id: 'zip_bomb',
          title: `Possible zip bomb (≈${Math.round(arc.ratio)}× compression)`,
          detail: `The archive expands from ${fmtBytes(arc.totalCompressed)} to ${fmtBytes(arc.totalUncompressed)} (${Math.round(arc.ratio)}× ratio). Decompression-bomb behaviour can exhaust memory/disk; Argus never extracts it.`,
          severity: 'high',
          weight: 50,
          confidence: 0.7,
        });
      }
      if (nested.length > 0) {
        finding(findings, signals, {
          id: 'nested_archive',
          title: `Archive contains ${nested.length} nested archive(s)`,
          detail: `Nested archives (${nested.slice(0, 3).join(', ')}${nested.length > 3 ? '…' : ''}) are used to wrap payloads and evade scanners.`,
          severity: 'low',
          weight: 16,
          confidence: 0.6,
        });
      }
    }
  }


  if (detected?.type === 'ole') {
    const markers = ['vbaProject', '_VBA_PROJECT', 'VBA_PROJECT', 'Auto_Open', 'AutoOpen', 'Workbook_Open', 'Document_Open', 'Macros'];
    const hit = markers.filter((m) => text.includes(m));
    if (hit.length > 0) {
      finding(findings, signals, {
        id: 'ole_macro',
        title: 'Legacy Office document with VBA-macro markers',
        detail: `Found VBA indicators (${hit.slice(0, 4).join(', ')}). Legacy .doc/.xls macros are a classic infection vector.`,
        severity: 'high',
        weight: 52,
        confidence: 0.7,
      });
    }
  }


  if (detected?.type === 'pdf') {
    const checks: Array<[RegExp, string, number, StaticFinding['severity']]> = [
      [/\/JavaScript/g, 'JavaScript', 50, 'high'],
      [/\/JS\b/g, 'JS action', 40, 'medium'],
      [/\/OpenAction/g, 'auto-run OpenAction', 40, 'medium'],
      [/\/AA\b/g, 'additional auto-actions', 30, 'medium'],
      [/\/Launch/g, 'Launch (external program) action', 55, 'high'],
      [/\/EmbeddedFile/g, 'embedded file', 35, 'medium'],
      [/\/RichMedia/g, 'RichMedia/Flash', 30, 'medium'],
    ];
    const present = checks.filter(([re]) => re.test(text));
    if (present.length > 0) {
      const top = present.reduce((a, b) => (b[2] > a[2] ? b : a));
      finding(findings, signals, {
        id: 'pdf_active',
        title: `PDF contains active content (${present.map((p) => p[1]).join(', ')})`,
        detail: `The PDF embeds active features: ${present.map((p) => p[1]).join(', ')}. Benign PDFs rarely need JavaScript, auto-actions or launch actions - these are common in weaponised documents.`,
        severity: top[3],
        weight: top[2],
        confidence: 0.65,
      });
    }
  }


  if (detected?.type === 'pe') {
    const pe = parsePeDetail(buf);
    if (pe) {
      result.pe = pe;
      finding(findings, signals, {
        id: 'pe_binary',
        title: `Windows executable (${pe.machine}${pe.isDll ? ' DLL' : pe.isDriver ? ' driver' : ''}, ${pe.subsystem})`,
        detail: `Native Windows ${pe.isDriver ? 'driver' : pe.isDll ? 'DLL' : 'executable'}, ${pe.sections.length} sections${
          pe.imphash ? `, imphash ${pe.imphash}` : ''
        }. ${pe.signed ? 'Carries an Authenticode signature.' : 'Unsigned.'} Argus analyses but never runs it.`,
        severity: 'medium',
        weight: 30,
        confidence: 0.7,
      });
      if (pe.suspiciousImports.length >= 2) {
        finding(findings, signals, {
          id: 'pe_suspicious_imports',
          title: `Imports process-injection / download-exec APIs (${pe.suspiciousImports.slice(0, 4).join(', ')})`,
          detail: `The executable imports ${pe.suspiciousImports.length} high-risk Windows APIs commonly used for code injection, anti-debugging, or download-and-execute: ${pe.suspiciousImports.join(', ')}.`,
          severity: 'high',
          weight: 56,
          confidence: 0.7,
        });
      }
      const packedSection = pe.sections.find((s) => s.entropy > 7.2 && s.size > 1024);
      if (pe.packerHint || packedSection) {
        finding(findings, signals, {
          id: 'pe_packed',
          title: pe.packerHint ? `Executable appears packed (${pe.packerHint})` : `High-entropy section (${packedSection!.name})`,
          detail: pe.packerHint
            ? `Section names indicate the ${pe.packerHint} packer. Packing hides code from static scanners - common in malware.`
            : `Section “${packedSection!.name}” has near-random entropy (${packedSection!.entropy}/8), a hallmark of packed/encrypted code.`,
          severity: 'medium',
          weight: 34,
          confidence: 0.6,
        });
      }
      if (pe.isDriver) {
        finding(findings, signals, {
          id: 'pe_driver',
          title: 'Kernel-mode driver',
          detail: 'This is a native kernel driver (ring 0). Malicious drivers can disable security software and hide deeply; only load drivers from fully trusted vendors.',
          severity: 'medium',
          weight: 30,
          confidence: 0.6,
        });
      }
    }
  }


  if (detected?.type === 'script' || detected === undefined) {
    const patterns: Array<[RegExp, string]> = [
      [/powershell\s+-(enc|encodedcommand|e )/i, 'encoded PowerShell command'],
      [/FromBase64String/i, 'base64-decoded payload'],
      [/Invoke-Expression|\bIEX\b/i, 'PowerShell Invoke-Expression'],
      [/eval\s*\(\s*(atob|unescape|String\.fromCharCode)/i, 'JS eval of decoded data'],
      [/document\.write\s*\(\s*unescape/i, 'document.write(unescape(...))'],
      [/(WScript\.Shell|ActiveXObject)/i, 'Windows Script Host / ActiveX'],
      [/-nop\s+-w\s+hidden|-windowstyle\s+hidden/i, 'hidden-window execution'],
    ];
    const hits = patterns.filter(([re]) => re.test(text)).map(([, label]) => label);
    const b64 = /[A-Za-z0-9+/]{200,}={0,2}/.test(text);
    if (hits.length > 0) {
      finding(findings, signals, {
        id: 'script_obfuscation',
        title: `Suspicious script behaviour (${hits.slice(0, 3).join(', ')})`,
        detail: `The content uses download/execute or obfuscation techniques: ${hits.join(', ')}${b64 ? ', plus a long base64 blob' : ''}.`,
        severity: 'high',
        weight: 50,
        confidence: 0.6,
        category: 'static',
      });
    } else if (b64 && buf.length < 200_000) {
      finding(findings, signals, {
        id: 'long_base64',
        title: 'Large embedded base64 blob',
        detail: 'A long base64-encoded blob is present. Sometimes benign, but also used to smuggle encoded payloads.',
        severity: 'low',
        weight: 14,
        confidence: 0.45,
      });
    }
  }


  result.iocs.push(...extractIocs(text));

  return result;
}


function fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(1)} GB`;
}

const PRIVATE_IP = /^(10\.|127\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|0\.)/;

export function extractIocs(text: string): Ioc[] {
  const iocs: Ioc[] = [];
  const seen = new Set<string>();
  const push = (type: Ioc['type'], value: string) => {
    const key = `${type}:${value}`;
    if (seen.has(key) || iocs.length >= 50) return;
    seen.add(key);
    iocs.push({ type, value });
  };
  for (const m of text.matchAll(/https?:\/\/[^\s"'<>)\]]{4,200}/gi)) push('url', m[0]);
  for (const m of text.matchAll(/\b[a-z2-7]{16,56}\.onion\b/gi)) push('onion', m[0]);
  for (const m of text.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) {
    if (!PRIVATE_IP.test(m[0])) push('ip', m[0]);
  }
  for (const m of text.matchAll(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g)) push('email', m[0]);
  for (const m of text.matchAll(/\bCVE-\d{4}-\d{4,7}\b/gi)) push('cve', m[0].toUpperCase());

  for (const m of text.matchAll(/\b(?:bc1[a-z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b/g)) push('btc', m[0]);
  for (const m of text.matchAll(/\b0x[a-fA-F0-9]{40}\b/g)) push('eth', m[0]);

  for (const m of text.matchAll(/\b(?:HKLM|HKCU|HKEY_[A-Z_]+)\\[\\A-Za-z0-9 ._-]{6,120}/g)) push('registry', m[0]);
  return iocs;
}
