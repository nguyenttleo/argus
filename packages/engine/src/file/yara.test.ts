import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseYaraRules, scanBytes, compileAndScan } from './yara.ts';

// Malicious fixtures are decoded at runtime (base64 / concatenation) so this source
// file never contains a contiguous live signature - otherwise endpoint AV (Windows
// Defender) quarantines the test file. This is the same reason real AV/YARA projects
// ship their samples encoded.
const EICAR = Buffer.from(
  'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=',
  'base64',
).toString('latin1');
const WEBSHELL = '<' + '?php @' + 'eval($' + '_POST["x"]); ?>'; // broken up on purpose

const builtinPath = fileURLToPath(new URL('../../rules/builtin.yar', import.meta.url));
const builtin = readFileSync(builtinPath, 'utf8');

function buf(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

test('built-in rules parse with no errors', () => {
  const { rules, errors } = parseYaraRules(builtin);
  assert.deepEqual(errors, [], `parse errors: ${errors.join('; ')}`);
  assert.ok(rules.length >= 7);
  assert.ok(rules.some((r) => r.name === 'EICAR_Test_File'));
});

test('EICAR string is detected by the built-in rule', () => {
  const { matches } = compileAndScan(builtin, buf(EICAR));
  assert.ok(matches.some((m) => m.rule === 'EICAR_Test_File'), `got ${matches.map((m) => m.rule)}`);
  const eicar = matches.find((m) => m.rule === 'EICAR_Test_File')!;
  assert.equal(eicar.meta.severity, 'critical');
  assert.equal(eicar.meta.weight, 100);
});

test('uint16(0)==0x5A4D MZ check + "2 of ($a*)" fires on a fake malicious PE', () => {
  const bytes = new Uint8Array([0x4d, 0x5a, ...buf('....VirtualAllocEx....WriteProcessMemory....')]);
  const { matches } = compileAndScan(builtin, bytes);
  assert.ok(matches.some((m) => m.rule === 'Suspicious_PE_Imports'), `got ${matches.map((m) => m.rule)}`);
});

test('a PE with only one suspicious import does NOT trip "2 of"', () => {
  const bytes = new Uint8Array([0x4d, 0x5a, ...buf('....VirtualAllocEx....nothing else....')]);
  const { matches } = compileAndScan(builtin, bytes);
  assert.ok(!matches.some((m) => m.rule === 'Suspicious_PE_Imports'));
});

test('PDF with /JavaScript is flagged; plain PDF is not', () => {
  const evil = compileAndScan(builtin, buf('%PDF-1.7\n/OpenAction /JavaScript (app.alert(1))')).matches;
  assert.ok(evil.some((m) => m.rule === 'PDF_Active_Content'));
  const clean = compileAndScan(builtin, buf('%PDF-1.7\nhello world plain pdf')).matches;
  assert.ok(!clean.some((m) => m.rule === 'PDF_Active_Content'));
});

test('PHP webshell regex string matches', () => {
  const { matches } = compileAndScan(builtin, buf(WEBSHELL));
  assert.ok(matches.some((m) => m.rule === 'PHP_Webshell_Generic'));
});

test('Office macro auto-exec hooks match', () => {
  const { matches } = compileAndScan(builtin, buf('PK....word/vbaProject.bin....AutoOpen'));
  assert.ok(matches.some((m) => m.rule === 'Office_VBA_Macro'));
});

test('a benign text file matches nothing', () => {
  const { matches } = compileAndScan(builtin, buf('Dear team, please find the meeting notes attached. Thanks!'));
  assert.deepEqual(matches, []);
});

// ── engine feature coverage with focused inline rules ──

test('hex strings with wildcards and jumps', () => {
  const rule = `rule H { strings: $h = { 4D 5A ?? ?? [2-6] FF FE } condition: $h }`;
  const yes = new Uint8Array([0x4d, 0x5a, 0x11, 0x22, 0, 0, 0, 0xff, 0xfe]);
  const no = new Uint8Array([0x4d, 0x5a, 0x11, 0x22, 0xff, 0xfe]);
  assert.equal(scanBytes(yes, parseYaraRules(rule).rules).length, 1);
  assert.equal(scanBytes(no, parseYaraRules(rule).rules).length, 0);
});

test('filesize and comparison operators', () => {
  const rule = `rule S { strings: $a = "x" condition: $a and filesize < 10 }`;
  assert.equal(compileAndScan(rule, buf('xyz')).matches.length, 1);
  assert.equal(compileAndScan(rule, buf('x'.repeat(20))).matches.length, 0);
});

test('"$a at 0" anchors a match to an offset', () => {
  const rule = `rule A { strings: $a = "MZ" condition: $a at 0 }`;
  assert.equal(compileAndScan(rule, buf('MZhello')).matches.length, 1);
  assert.equal(compileAndScan(rule, buf('xxMZ')).matches.length, 0);
});

test('count (#a) and nocase modifier', () => {
  const rule = `rule C { strings: $a = "ab" nocase condition: #a >= 2 }`;
  assert.equal(compileAndScan(rule, buf('ABxxab')).matches.length, 1);
  assert.equal(compileAndScan(rule, buf('ABxx')).matches.length, 0);
});

test('all / any / N of them quantifiers and boolean logic', () => {
  const rule = `rule Q { strings: $a="a" $b="b" $c="c" condition: (all of them) or (2 of them and not $c) }`;
  assert.equal(compileAndScan(rule, buf('abc')).matches.length, 1);
  assert.equal(compileAndScan(rule, buf('ab')).matches.length, 1);
  assert.equal(compileAndScan(rule, buf('ac')).matches.length, 0);
});

test('malformed rule is skipped, not fatal', () => {
  const rule = `rule Bad { condition: $missing and ( }
               rule Good { strings: $a = "ok" condition: $a }`;
  const { rules, errors } = parseYaraRules(rule);
  assert.ok(errors.length >= 1);
  assert.ok(rules.some((r) => r.name === 'Good'));
});
