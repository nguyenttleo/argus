import { createHash } from 'node:crypto';

export interface FileHashes {
  sha256: string;
  sha1: string;
  md5: string;
}


export function hashBytes(buf: Uint8Array): FileHashes {
  return {
    sha256: createHash('sha256').update(buf).digest('hex'),
    sha1: createHash('sha1').update(buf).digest('hex'),
    md5: createHash('md5').update(buf).digest('hex'),
  };
}


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
