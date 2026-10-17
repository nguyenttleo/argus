import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { mkdirSync, readdirSync, readFileSync, statSync, unlinkSync, writeFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const IV_LEN = 12;
const TAG_LEN = 16;

export interface QuarantineOptions {
  dir: string;
  key: Buffer;
  ttlMs: number;
}

export class Quarantine {
  #dir: string;
  #key: Buffer;
  #ttlMs: number;

  constructor(opts: QuarantineOptions) {
    if (opts.key.length !== 32) throw new Error('quarantine key must be 32 bytes');
    this.#dir = opts.dir;
    this.#key = opts.key;
    this.#ttlMs = opts.ttlMs;
    mkdirSync(this.#dir, { recursive: true });
  }

  #path(sha256: string): string {
    return join(this.#dir, `${sha256}.enc`);
  }

  store(bytes: Uint8Array, sha256: string): string {
    const iv = randomBytes(IV_LEN);
    const cipher = createCipheriv('aes-256-gcm', this.#key, iv);
    const ct = Buffer.concat([cipher.update(bytes), cipher.final()]);
    const tag = cipher.getAuthTag();
    writeFileSync(this.#path(sha256), Buffer.concat([iv, tag, ct]), { mode: 0o600 });
    return sha256;
  }

  has(sha256: string): boolean {
    return existsSync(this.#path(sha256));
  }

  retrieve(sha256: string): Uint8Array | undefined {
    const p = this.#path(sha256);
    if (!existsSync(p)) return undefined;
    const blob = readFileSync(p);
    const iv = blob.subarray(0, IV_LEN);
    const tag = blob.subarray(IV_LEN, IV_LEN + TAG_LEN);
    const ct = blob.subarray(IV_LEN + TAG_LEN);
    const decipher = createDecipheriv('aes-256-gcm', this.#key, iv);
    decipher.setAuthTag(tag);
    return new Uint8Array(Buffer.concat([decipher.update(ct), decipher.final()]));
  }

  sweep(now: number = Date.now()): number {
    if (!existsSync(this.#dir)) return 0;
    let removed = 0;
    for (const f of readdirSync(this.#dir)) {
      if (!f.endsWith('.enc')) continue;
      const p = join(this.#dir, f);
      try {
        if (now - statSync(p).mtimeMs > this.#ttlMs) {
          unlinkSync(p);
          removed++;
        }
      } catch {}
    }
    return removed;
  }
}

export function resolveQuarantineKey(dataDir: string, secret?: string): Buffer {
  if (secret) {

    return scryptSync(secret, 'argus-quarantine-salt', 32);
  }
  const keyPath = join(dataDir, 'quarantine.key');
  if (existsSync(keyPath)) return readFileSync(keyPath);
  mkdirSync(dataDir, { recursive: true });
  const key = randomBytes(32);
  writeFileSync(keyPath, key, { mode: 0o600 });
  return key;
}
