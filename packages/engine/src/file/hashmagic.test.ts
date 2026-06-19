import { test } from 'node:test';
import assert from 'node:assert/strict';
import { hashBytes, shannonEntropy } from './hash.ts';
import { detectType, checkTypeMismatch, extOf } from './magic.ts';

const enc = (s: string) => new TextEncoder().encode(s);

test('sha256/sha1/md5 of known input', () => {
  const h = hashBytes(enc('abc'));
  assert.equal(h.sha256, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(h.sha1, 'a9993e364706816aba3e25717850c26c9cd0d89d');
  assert.equal(h.md5, '900150983cd24fb0d6963f7d28e17f72');
});

test('entropy: uniform low, random high', () => {
  assert.equal(shannonEntropy(new Uint8Array(0)), 0);
  assert.equal(shannonEntropy(new Uint8Array(100).fill(65)), 0); // all same byte
  const allBytes = new Uint8Array(256);
  for (let i = 0; i < 256; i++) allBytes[i] = i;
  assert.equal(shannonEntropy(allBytes), 8); // perfectly uniform
});

test('detectType identifies common formats by magic bytes', () => {
  assert.equal(detectType(new Uint8Array([0x4d, 0x5a, 0x90]))?.type, 'pe');
  assert.equal(detectType(new Uint8Array([0x7f, 0x45, 0x4c, 0x46]))?.type, 'elf');
  assert.equal(detectType(enc('%PDF-1.7'))?.type, 'pdf');
  assert.equal(detectType(new Uint8Array([0x50, 0x4b, 0x03, 0x04]))?.type, 'zip');
  assert.equal(detectType(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))?.type, 'png');
  assert.equal(detectType(new Uint8Array([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]))?.type, 'ole');
  assert.equal(detectType(enc('just text')), undefined);
});

test('extOf extracts lowercase extension', () => {
  assert.equal(extOf('invoice.PDF'), 'pdf');
  assert.equal(extOf('archive.tar.gz'), 'gz');
  assert.equal(extOf('noext'), '');
  assert.equal(extOf('.gitignore'), '');
});

test('checkTypeMismatch detects executable masquerade', () => {
  const pe = new Uint8Array([0x4d, 0x5a, 0x90, 0x00]);
  const m = checkTypeMismatch(pe, 'cute-cat.jpg');
  assert.equal(m.mismatch, true);
  assert.equal(m.executableMasquerade, true);
  // matching extension → no mismatch
  assert.equal(checkTypeMismatch(pe, 'tool.exe').mismatch, false);
  // png named .png → consistent
  assert.equal(checkTypeMismatch(new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), 'pic.png').mismatch, false);
});
