import { createHash } from 'node:crypto';

export interface FileHashes {
  sha256: string;
  sha1: string;
  md5: string;
}

/** Hash the bytes three ways (sha256 is canonical; sha1/md5 aid feed lookups). */
export function hashBytes(buf: Uint8Array): FileHashes {
  return {
    sha256: createHash('sha256').update(buf).digest('hex'),
    sha1: createHash('sha1').update(buf).digest('hex'),
    md5: createHash('md5').update(buf).digest('hex'),
  };
}

/**
 * Shannon entropy in bits/byte (0–8). Values above ~7.2 on a file that *isn't*
 * a compressed/media container suggest packing or encryption - a common way to
 * hide malware from signature scanners.
 */
export function shannonEntropy(buf: Uint8Array): number {
  if (buf.length === 0) return 0;
  const counts = new Uint32Array(256);
  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i] as number;
    counts[byte] = (counts[byte] as number) + 1;
  }
  let e = 0;
  for (let i = 0; i < 256; i++) {
    const c = counts[i] as number;
    if (c) {
      const p = c / buf.length;
      e -= p * Math.log2(p);
    }
  }
  return e;
}
