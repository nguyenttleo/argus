import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, existsSync, utimesSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomBytes } from 'node:crypto';
import { Quarantine } from './quarantine.ts';

function tmp(): string {
  return mkdtempSync(join(tmpdir(), 'argus-q-'));
}

test('store → retrieve round-trips through AES-256-GCM', () => {
  const dir = tmp();
  try {
    const q = new Quarantine({ dir, key: randomBytes(32), ttlMs: 10_000 });
    const data = new Uint8Array([1, 2, 3, 4, 250, 0, 99]);
    const ref = q.store(data, 'a'.repeat(64));
    assert.equal(q.has(ref), true);
    assert.deepEqual([...q.retrieve(ref)!], [...data]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('on-disk blob is encrypted (not the plaintext)', () => {
  const dir = tmp();
  try {
    const q = new Quarantine({ dir, key: randomBytes(32), ttlMs: 10_000 });
    const plaintext = Buffer.from('SENSITIVE-MALWARE-MARKER');
    const sha = 'b'.repeat(64);
    q.store(new Uint8Array(plaintext), sha);
    const onDisk = readFileSync(join(dir, `${sha}.enc`));
    assert.ok(!onDisk.includes(plaintext), 'ciphertext must not contain the plaintext marker');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('wrong key fails authentication (GCM tag)', () => {
  const dir = tmp();
  try {
    const q1 = new Quarantine({ dir, key: randomBytes(32), ttlMs: 10_000 });
    q1.store(new Uint8Array([9, 9, 9]), 'c'.repeat(64));
    const q2 = new Quarantine({ dir, key: randomBytes(32), ttlMs: 10_000 });
    assert.throws(() => q2.retrieve('c'.repeat(64)));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('sweep removes entries older than the TTL', () => {
  const dir = tmp();
  try {
    const q = new Quarantine({ dir, key: randomBytes(32), ttlMs: 1000 });
    const sha = 'd'.repeat(64);
    q.store(new Uint8Array([1]), sha);
    const p = join(dir, `${sha}.enc`);
    // backdate the file 1 hour
    const old = new Date(Date.now() - 3600_000);
    utimesSync(p, old, old);
    const removed = q.sweep();
    assert.equal(removed, 1);
    assert.equal(existsSync(p), false);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('key must be 32 bytes', () => {
  assert.throws(() => new Quarantine({ dir: tmp(), key: randomBytes(16), ttlMs: 1 }));
});
