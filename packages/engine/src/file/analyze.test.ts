import { test } from 'node:test';
import assert from 'node:assert/strict';
import { analyzeFile } from './analyze.ts';

const fixedDeps = { now: () => new Date('2026-01-01T00:00:00Z'), idGen: () => 'file-test' };
const EICAR = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';
const enc = (s: string) => new TextEncoder().encode(s);

function makeZip(name: string, uncompSize = 0, compSize = 0): Uint8Array {
  const nameBytes = enc(name);
  const N = nameBytes.length;
  const local = Buffer.alloc(30 + N);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0, 8);
  local.writeUInt32LE(compSize, 18);
  local.writeUInt32LE(uncompSize, 22);
  local.writeUInt16LE(N, 26);
  Buffer.from(nameBytes).copy(local, 30);

  const cd = Buffer.alloc(46 + N);
  cd.writeUInt32LE(0x02014b50, 0);
  cd.writeUInt16LE(20, 4);
  cd.writeUInt16LE(20, 6);
  cd.writeUInt32LE(compSize, 20);
  cd.writeUInt32LE(uncompSize, 24);
  cd.writeUInt16LE(N, 28);
  cd.writeUInt32LE(0, 42);
  Buffer.from(nameBytes).copy(cd, 46);

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(local.length, 16);

  return new Uint8Array(Buffer.concat([local, cd, eocd]));
}

test('EICAR is detected and decisively malicious', async () => {
  const r = await analyzeFile({ filename: 'eicar.com', bytes: enc(EICAR) }, {}, fixedDeps);
  assert.equal(r.verdict, 'malicious');
  assert.ok(r.score >= 92, `score ${r.score}`);
  assert.equal(r.detail.kind, 'file');
  if (r.detail.kind === 'file') {
    assert.equal(r.detail.sha256, '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');
    assert.ok(r.detail.yaraHits.some((h) => h.rule === 'EICAR_Test_File'));
  }

  assert.ok(r.signals.some((s) => s.id.startsWith('rep.')));
  assert.match(r.summary, /Do not open/);
});

test('benign text file is safe', async () => {
  const r = await analyzeFile({ filename: 'notes.txt', bytes: enc('Meeting notes: ship the release on Friday.') }, {}, fixedDeps);
  assert.equal(r.verdict, 'safe');
  assert.equal(r.score, 0);
});

test('executable disguised as a PDF is flagged (magic mismatch)', async () => {

  const bytes = new Uint8Array([0x4d, 0x5a, ...enc('this is really a windows executable not a pdf')]);
  const r = await analyzeFile({ filename: 'invoice.pdf', bytes }, {}, fixedDeps);
  assert.ok(r.signals.some((s) => s.id === 'file.exe_masquerade'), `signals: ${r.signals.map((s) => s.id)}`);
  assert.notEqual(r.verdict, 'safe');
  if (r.detail.kind === 'file') assert.equal(r.detail.typeMismatch, true);
});

test('a PE with process-injection imports trips the YARA rule', async () => {

  const head = Buffer.alloc(0x80);
  head.writeUInt16LE(0x5a4d, 0);
  head.writeUInt32LE(0x40, 0x3c);
  head.writeUInt32LE(0x00004550, 0x40);
  const body = enc('....VirtualAllocEx....WriteProcessMemory....CreateRemoteThread....');
  const r = await analyzeFile({ filename: 'sample.exe', bytes: new Uint8Array(Buffer.concat([head, Buffer.from(body)])) }, {}, fixedDeps);
  assert.ok(r.signals.some((s) => s.id === 'yara.Suspicious_PE_Imports'));
  assert.ok(r.signals.some((s) => s.id === 'static.pe_binary'));
});

test('PDF with JavaScript yields active-content findings', async () => {
  const r = await analyzeFile({ filename: 'doc.pdf', bytes: enc('%PDF-1.7\n/OpenAction <</JS (app.alert(1))>> /JavaScript') }, {}, fixedDeps);
  assert.ok(r.signals.some((s) => s.id === 'static.pdf_active'));
  assert.ok(r.signals.some((s) => s.id === 'yara.PDF_Active_Content'));
  assert.notEqual(r.verdict, 'safe');
});

test('OOXML with vbaProject.bin is detected as a macro document', async () => {
  const zip = makeZip('word/vbaProject.bin');
  const r = await analyzeFile({ filename: 'report.docx', bytes: zip }, {}, fixedDeps);
  assert.ok(r.signals.some((s) => s.id === 'static.ooxml_macro'), `signals: ${r.signals.map((s) => s.id)}`);
  if (r.detail.kind === 'file') assert.ok(r.detail.realType === 'zip');
});

test('zip bomb ratio is flagged', async () => {

  const zip = makeZip('big.bin', 200 * 1024 * 1024, 1024);
  const r = await analyzeFile({ filename: 'archive.zip', bytes: zip }, {}, fixedDeps);
  assert.ok(r.signals.some((s) => s.id === 'static.zip_bomb'), `signals: ${r.signals.map((s) => s.id)}`);
});

test('IOCs are extracted from file content', async () => {
  const r = await analyzeFile(
    { filename: 'payload.txt', bytes: enc('callback to http://evil.example.com/c2 and 203.0.113.50 mail admin@evil.example.com') },
    {},
    fixedDeps,
  );
  assert.ok(r.iocs.some((i) => i.type === 'url' && i.value.includes('evil.example.com')));
  assert.ok(r.iocs.some((i) => i.type === 'ip' && i.value === '203.0.113.50'));
  assert.ok(r.iocs.some((i) => i.type === 'email'));
  assert.ok(r.iocs.some((i) => i.type === 'sha256'));
});

test('report shape and timing are populated', async () => {
  const r = await analyzeFile({ filename: 'x.txt', bytes: enc('hello') }, {}, fixedDeps);
  assert.equal(r.id, 'file-test');
  assert.equal(r.kind, 'file');
  assert.equal(r.engineVersion, '1.2.7');
  assert.ok(typeof r.confidence === 'number');
});

test('detonation hook is invoked only when opted in + configured', async () => {
  let called = 0;
  const detonate = async () => {
    called++;
    return { available: true, ran: true, source: 'tartarus' as const, detail: 'ran', iocs: [{ type: 'domain' as const, value: 'c2.evil.test' }] };
  };

  await analyzeFile({ filename: 'a.py', bytes: enc('print(1)') }, { detonate: true }, { ...fixedDeps, detonate });
  assert.equal(called, 0, 'should not detonate without TARTARUS_URL');

  const r = await analyzeFile(
    { filename: 'a.py', bytes: enc('import os') },
    { detonate: true },
    { ...fixedDeps, detonate, config: { reputationTimeoutMs: 500, fetchTimeoutMs: 500, maxFetchBytes: 1024, tartarusUrl: 'http://localhost:8080' } },
  );
  assert.equal(called, 1);
  assert.ok(r.signals.some((s) => s.id === 'detonation.behavioral_iocs'));
  assert.ok(r.iocs.some((i) => i.value === 'c2.evil.test'));
});
