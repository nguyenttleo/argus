

import { createHash } from 'node:crypto';
import type { PeDetail, PeSection } from '@argus/shared';
import { shannonEntropy } from './hash.ts';

function u8(b: Uint8Array, o: number): number {
  return o >= 0 && o < b.length ? b[o]! : 0;
}
function u16(b: Uint8Array, o: number): number {
  return o + 2 <= b.length ? b[o]! | (b[o + 1]! << 8) : 0;
}
function u32(b: Uint8Array, o: number): number {
  return o + 4 <= b.length ? (b[o]! | (b[o + 1]! << 8) | (b[o + 2]! << 16) | (b[o + 3]! << 24)) >>> 0 : 0;
}

const SUSPICIOUS_APIS = new Set(
  [
    'VirtualAllocEx',
    'WriteProcessMemory',
    'CreateRemoteThread',
    'NtCreateThreadEx',
    'QueueUserAPC',
    'SetWindowsHookEx',
    'URLDownloadToFile',
    'URLDownloadToFileW',
    'WinExec',
    'ShellExecuteA',
    'ShellExecuteW',
    'CreateProcessA',
    'CreateProcessW',
    'IsDebuggerPresent',
    'CheckRemoteDebuggerPresent',
    'VirtualProtect',
    'VirtualProtectEx',
    'CryptEncrypt',
    'CryptDecrypt',
    'RegSetValueExA',
    'RegSetValueExW',
    'InternetOpenA',
    'InternetOpenW',
    'InternetReadFile',
    'WSASocketA',
    'GetProcAddress',
    'LoadLibraryA',
    'LoadLibraryW',
    'GetAsyncKeyState',
    'SetThreadContext',
  ].map((s) => s.toLowerCase()),
);

const STRIP_EXT = ['.dll', '.sys', '.ocx', '.cpl', '.exe', '.drv'];

interface Sections {
  list: PeSection[];
  toOffset(rva: number): number;
}

export function parsePeDetail(buf: Uint8Array): PeDetail | undefined {
  if (u16(buf, 0) !== 0x5a4d) return undefined;
  const peOff = u32(buf, 0x3c);
  if (peOff <= 0 || peOff + 24 > buf.length || u32(buf, peOff) !== 0x00004550) return undefined;

  const machineCode = u16(buf, peOff + 4);
  const numSections = u16(buf, peOff + 6);
  const timeDateStamp = u32(buf, peOff + 8);
  const sizeOfOptional = u16(buf, peOff + 20);
  const characteristics = u16(buf, peOff + 22);

  const optOff = peOff + 24;
  const magic = u16(buf, optOff);
  const isPlus = magic === 0x20b;
  const subsystem = u16(buf, optOff + 68);
  const dllChars = u16(buf, optOff + 70);
  void dllChars;

  const dirCountOff = optOff + (isPlus ? 108 : 92);
  const numDirs = u32(buf, dirCountOff);
  const dirsOff = optOff + (isPlus ? 112 : 96);
  const dir = (i: number): { rva: number; size: number } =>
    i < numDirs ? { rva: u32(buf, dirsOff + i * 8), size: u32(buf, dirsOff + i * 8 + 4) } : { rva: 0, size: 0 };


  const secStart = optOff + sizeOfOptional;
  const sections: PeSection[] = [];
  const rawSecs: { va: number; vsize: number; ptr: number; rsize: number }[] = [];
  for (let i = 0; i < Math.min(numSections, 96); i++) {
    const off = secStart + i * 40;
    if (off + 40 > buf.length) break;
    const name = bytesToAscii(buf.subarray(off, off + 8)).replace(/\0+$/, '');
    const vsize = u32(buf, off + 8);
    const va = u32(buf, off + 12);
    const rsize = u32(buf, off + 16);
    const ptr = u32(buf, off + 20);
    rawSecs.push({ va, vsize, ptr, rsize });
    const slice = ptr + rsize <= buf.length && rsize > 0 ? buf.subarray(ptr, ptr + Math.min(rsize, 2_000_000)) : new Uint8Array();
    sections.push({ name, size: rsize, entropy: Number(shannonEntropy(slice).toFixed(2)) });
  }

  const secs: Sections = {
    list: sections,
    toOffset(rva: number): number {
      for (const s of rawSecs) {
        if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rsize)) return s.ptr + (rva - s.va);
      }
      return -1;
    },
  };


  const importDir = dir(1);
  const imp = parseImports(buf, secs, importDir.rva, isPlus);

  const machine =
    machineCode === 0x8664 ? 'x64' : machineCode === 0x14c ? 'x86' : machineCode === 0xaa64 ? 'ARM64' : `0x${machineCode.toString(16)}`;
  const sub =
    subsystem === 2 ? 'GUI' : subsystem === 3 ? 'console' : subsystem === 1 ? 'native' : subsystem === 9 ? 'WinCE' : `subsystem ${subsystem}`;

  let packerHint: string | undefined;
  const secNames = sections.map((s) => s.name.toLowerCase());
  if (secNames.some((n) => n.startsWith('upx'))) packerHint = 'UPX';
  else if (secNames.includes('.aspack')) packerHint = 'ASPack';
  else if (secNames.some((n) => n.includes('themida'))) packerHint = 'Themida';
  else if (secNames.includes('.petite')) packerHint = 'Petite';

  return {
    machine,
    subsystem: sub,
    isDll: (characteristics & 0x2000) !== 0,
    isDriver: subsystem === 1 && (characteristics & 0x2000) === 0,
    sections,
    imphash: imp.imphash,
    importedDlls: imp.dlls,
    suspiciousImports: imp.suspicious,
    signed: dir(4).size > 0,
    hasResources: dir(2).size > 0,
    hasTls: dir(9).size > 0,
    packerHint,
    compiledAt: timeDateStamp > 0 && timeDateStamp < 0xffffffff ? new Date(timeDateStamp * 1000).toISOString() : undefined,
  };
}

function parseImports(
  buf: Uint8Array,
  secs: Sections,
  importRva: number,
  isPlus: boolean,
): { dlls: string[]; suspicious: string[]; imphash?: string } {
  const dlls: string[] = [];
  const suspicious = new Set<string>();
  const impEntries: string[] = [];
  if (importRva <= 0) return { dlls, suspicious: [], imphash: undefined };
  let descOff = secs.toOffset(importRva);
  if (descOff < 0) return { dlls, suspicious: [], imphash: undefined };

  for (let d = 0; d < 1000; d++) {
    const off = descOff + d * 20;
    if (off + 20 > buf.length) break;
    const iltRva = u32(buf, off);
    const nameRva = u32(buf, off + 12);
    const iatRva = u32(buf, off + 16);
    if (iltRva === 0 && nameRva === 0 && iatRva === 0) break;

    const nameOff = secs.toOffset(nameRva);
    let dllName = nameOff >= 0 ? readCString(buf, nameOff, 256) : '';
    if (!dllName) continue;
    dlls.push(dllName);
    let lib = dllName.toLowerCase();
    for (const e of STRIP_EXT) if (lib.endsWith(e)) lib = lib.slice(0, -e.length);

    const thunkRva = iltRva || iatRva;
    let thunkOff = secs.toOffset(thunkRva);
    const tsize = isPlus ? 8 : 4;
    for (let t = 0; t < 5000 && thunkOff >= 0; t++) {
      const entOff = thunkOff + t * tsize;
      if (entOff + tsize > buf.length) break;
      const lo = u32(buf, entOff);
      const hi = isPlus ? u32(buf, entOff + 4) : 0;
      if (lo === 0 && hi === 0) break;
      const byOrdinal = isPlus ? (hi & 0x80000000) !== 0 : (lo & 0x80000000) !== 0;
      let func: string;
      if (byOrdinal) {
        func = `ord${lo & 0xffff}`;
      } else {
        const hintNameOff = secs.toOffset(lo);
        const fname = hintNameOff >= 0 ? readCString(buf, hintNameOff + 2, 256) : '';
        if (!fname) continue;
        func = fname.toLowerCase();
        if (SUSPICIOUS_APIS.has(func)) suspicious.add(fname);
      }
      impEntries.push(`${lib}.${func}`);
    }
  }

  const imphash = impEntries.length ? createHash('md5').update(impEntries.join(',')).digest('hex') : undefined;
  return { dlls: dlls.slice(0, 30), suspicious: [...suspicious], imphash };
}

function bytesToAscii(b: Uint8Array): string {
  let s = '';
  for (const c of b) s += c >= 32 && c < 127 ? String.fromCharCode(c) : c === 0 ? '\0' : '';
  return s;
}
function readCString(b: Uint8Array, off: number, max: number): string {
  let s = '';
  for (let i = 0; i < max && off + i < b.length; i++) {
    const c = b[off + i]!;
    if (c === 0) break;
    if (c >= 32 && c < 127) s += String.fromCharCode(c);
  }
  return s;
}
