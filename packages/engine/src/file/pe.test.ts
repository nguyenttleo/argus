import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { parsePeDetail } from './pe.ts';
import { extractIocs } from './static.ts';

function makePe(): Uint8Array {
  const b = Buffer.alloc(0x300);
  b.writeUInt16LE(0x5a4d, 0);
  b.writeUInt32LE(0x40, 0x3c);
  const pe = 0x40;
  b.writeUInt32LE(0x00004550, pe);
  b.writeUInt16LE(0x14c, pe + 4);
  b.writeUInt16LE(1, pe + 6);
  b.writeUInt32LE(0x5a000000, pe + 8);
  b.writeUInt16LE(224, pe + 20);
  b.writeUInt16LE(0x0102, pe + 22);
  const opt = pe + 24;
  b.writeUInt16LE(0x10b, opt);
  b.writeUInt16LE(2, opt + 68);
  b.writeUInt32LE(16, opt + 92);
  const dirs = opt + 96;
  b.writeUInt32LE(0x1000, dirs + 8);
  b.writeUInt32LE(40, dirs + 12);
  const sec = opt + 224;
  b.write('.text\0\0\0', sec, 'latin1');
  b.writeUInt32LE(0x200, sec + 8);
  b.writeUInt32LE(0x1000, sec + 12);
  b.writeUInt32LE(0x100, sec + 16);
  b.writeUInt32LE(0x200, sec + 20);
  const raw = 0x200;
  b.writeUInt32LE(0x1020, raw + 0);
  b.writeUInt32LE(0x1040, raw + 12);
  b.writeUInt32LE(0x1020, raw + 16);

  b.writeUInt32LE(0x1050, raw + 0x20);
  b.writeUInt32LE(0, raw + 0x24);
  b.write('KERNEL32.dll\0', raw + 0x40, 'latin1');
  b.writeUInt16LE(0, raw + 0x50);
  b.write('VirtualAllocEx\0', raw + 0x52, 'latin1');
  return new Uint8Array(b);
}

test('parsePeDetail extracts machine/subsystem and imports', () => {
  const pe = parsePeDetail(makePe());
  assert.ok(pe);
  assert.equal(pe!.machine, 'x86');
  assert.equal(pe!.subsystem, 'GUI');
  assert.equal(pe!.isDll, false);
  assert.ok(pe!.importedDlls.includes('KERNEL32.dll'));
  assert.ok(pe!.suspiciousImports.includes('VirtualAllocEx'));
  assert.equal(pe!.signed, false);
  assert.ok(pe!.sections.some((s) => s.name === '.text'));
});

test('imphash matches pefile algorithm (md5 of ordered dll.func, ext stripped, lowercased)', () => {
  const pe = parsePeDetail(makePe());
  const expected = createHash('md5').update('kernel32.virtualallocex').digest('hex');
  assert.equal(pe!.imphash, expected);
});

test('imphash is deterministic', () => {
  assert.equal(parsePeDetail(makePe())!.imphash, parsePeDetail(makePe())!.imphash);
});

test('non-PE input returns undefined', () => {
  assert.equal(parsePeDetail(new TextEncoder().encode('not a pe')), undefined);
  assert.equal(parsePeDetail(new Uint8Array([0x4d, 0x5a])), undefined);
});

test('truncated PE does not crash', () => {
  const full = makePe();
  for (const len of [0x41, 0x60, 0x140, 0x205]) {
    assert.doesNotThrow(() => parsePeDetail(full.subarray(0, len)));
  }
});

test('extractIocs finds crypto addresses, CVEs, onion, registry', () => {
  const text = [
    'ransom to 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa or bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq',
    'eth 0x742d35Cc6634C0532925a3b844Bc454e4438f44e',
    'exploits CVE-2021-44228 and cve-2017-0144',
    'c2 at expyuzz4wqqyqhjn.onion',
    'persist HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
  ].join('\n');
  const iocs = extractIocs(text);
  const t = (ty: string) => iocs.filter((i) => i.type === ty).map((i) => i.value);
  assert.ok(t('btc').length >= 2);
  assert.ok(t('eth').includes('0x742d35Cc6634C0532925a3b844Bc454e4438f44e'));
  assert.ok(t('cve').includes('CVE-2021-44228'));
  assert.ok(t('onion').some((v) => v.endsWith('.onion')));
  assert.ok(t('registry').length >= 1);
});
