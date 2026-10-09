import { test } from 'node:test';
import assert from 'node:assert/strict';
import { renderReport, exitCodeFor } from './render.ts';
import { analyzeUrl, analyzeFile } from '@argus/engine';

test('exitCodeFor maps verdict → CI exit code', () => {
  assert.equal(exitCodeFor('safe'), 0);
  assert.equal(exitCodeFor('suspicious'), 1);
  assert.equal(exitCodeFor('malicious'), 2);
});

test('renders a malicious URL report with verdict, score and signals (no color)', async () => {
  const r = await analyzeUrl('http://paypal.com@secure-paypa1-login.tk/webscr?cmd=verify', {});
  const text = renderReport(r, { color: false });
  assert.match(text, /MALICIOUS/);
  assert.match(text, /\/100/);
  assert.match(text, /Risk signals/);
  assert.match(text, /Embedded credentials/);

  assert.ok(!text.includes('\x1b['), 'should contain no ANSI codes when color disabled');
});

test('renders a safe report and shows mitigating evidence', async () => {
  const r = await analyzeUrl('https://www.google.com/', {});
  const text = renderReport(r, { color: false });
  assert.match(text, /SAFE/);
  assert.match(text, /Mitigating/);
});

test('color mode emits ANSI escapes', async () => {
  const r = await analyzeUrl('https://www.google.com/', {});
  assert.ok(renderReport(r, { color: true }).includes('\x1b['));
});

test('renders a file report with sha256 + yara line', async () => {
  const EICAR = Buffer.from(
    'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=',
    'base64',
  );
  const r = await analyzeFile({ filename: 'eicar.com', bytes: new Uint8Array(EICAR) }, {});
  const text = renderReport(r, { color: false });
  assert.match(text, /MALICIOUS/);
  assert.match(text, /sha256 275a021bbfb6489e54d471899f7db9d1/);
  assert.match(text, /yara: EICAR_Test_File/);
});
