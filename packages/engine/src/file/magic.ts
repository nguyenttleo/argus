

export interface DetectedType {
  type: string;
  label: string;
  mime: string;
  exts: string[];

  family: 'executable' | 'document' | 'archive' | 'image' | 'media' | 'script' | 'other';
}

interface Sig extends DetectedType {
  offset: number;
  bytes: number[];

  also?: { offset: number; bytes: number[] };
}

const b = (s: string): number[] => [...s].map((c) => c.charCodeAt(0));


const SIGNATURES: Sig[] = [
  { type: 'pe', label: 'Windows PE executable (EXE/DLL)', mime: 'application/vnd.microsoft.portable-executable', exts: ['exe', 'dll', 'sys', 'scr', 'ocx'], family: 'executable', offset: 0, bytes: b('MZ') },
  { type: 'elf', label: 'ELF executable (Linux/Unix)', mime: 'application/x-elf', exts: ['elf', 'so', 'bin', 'out'], family: 'executable', offset: 0, bytes: [0x7f, 0x45, 0x4c, 0x46] },
  { type: 'macho', label: 'Mach-O executable (macOS)', mime: 'application/x-mach-binary', exts: ['', 'dylib', 'bundle'], family: 'executable', offset: 0, bytes: [0xcf, 0xfa, 0xed, 0xfe] },
  { type: 'macho', label: 'Mach-O executable (macOS, 32-bit)', mime: 'application/x-mach-binary', exts: [''], family: 'executable', offset: 0, bytes: [0xce, 0xfa, 0xed, 0xfe] },
  { type: 'java', label: 'Java class / Mach-O fat binary', mime: 'application/java-vm', exts: ['class'], family: 'executable', offset: 0, bytes: [0xca, 0xfe, 0xba, 0xbe] },
  { type: 'dex', label: 'Android DEX', mime: 'application/x-dex', exts: ['dex'], family: 'executable', offset: 0, bytes: b('dex\n') },
  { type: 'wasm', label: 'WebAssembly module', mime: 'application/wasm', exts: ['wasm'], family: 'executable', offset: 0, bytes: [0x00, 0x61, 0x73, 0x6d] },
  { type: 'lnk', label: 'Windows shortcut (.lnk)', mime: 'application/x-ms-shortcut', exts: ['lnk'], family: 'executable', offset: 0, bytes: [0x4c, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00] },
  { type: 'ole', label: 'Legacy MS Office / OLE compound (doc/xls/ppt/msi)', mime: 'application/x-ole-storage', exts: ['doc', 'xls', 'ppt', 'msi', 'msg'], family: 'document', offset: 0, bytes: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] },
  { type: 'pdf', label: 'PDF document', mime: 'application/pdf', exts: ['pdf'], family: 'document', offset: 0, bytes: b('%PDF-') },
  { type: 'rtf', label: 'Rich Text Format', mime: 'application/rtf', exts: ['rtf'], family: 'document', offset: 0, bytes: b('{\\rtf') },
  { type: 'zip', label: 'ZIP archive (also docx/xlsx/jar/apk)', mime: 'application/zip', exts: ['zip', 'docx', 'xlsx', 'pptx', 'docm', 'xlsm', 'pptm', 'jar', 'apk', 'odt', 'ods'], family: 'archive', offset: 0, bytes: [0x50, 0x4b, 0x03, 0x04] },
  { type: 'zip', label: 'ZIP archive (empty/spanned)', mime: 'application/zip', exts: ['zip'], family: 'archive', offset: 0, bytes: [0x50, 0x4b, 0x05, 0x06] },
  { type: 'rar', label: 'RAR archive', mime: 'application/vnd.rar', exts: ['rar'], family: 'archive', offset: 0, bytes: b('Rar!\x1a\x07') },
  { type: '7z', label: '7-Zip archive', mime: 'application/x-7z-compressed', exts: ['7z'], family: 'archive', offset: 0, bytes: [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c] },
  { type: 'gzip', label: 'gzip archive', mime: 'application/gzip', exts: ['gz', 'tgz'], family: 'archive', offset: 0, bytes: [0x1f, 0x8b] },
  { type: 'bzip2', label: 'bzip2 archive', mime: 'application/x-bzip2', exts: ['bz2'], family: 'archive', offset: 0, bytes: b('BZh') },
  { type: 'xz', label: 'xz archive', mime: 'application/x-xz', exts: ['xz'], family: 'archive', offset: 0, bytes: [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00] },
  { type: 'cab', label: 'Microsoft Cabinet', mime: 'application/vnd.ms-cab-compressed', exts: ['cab'], family: 'archive', offset: 0, bytes: b('MSCF') },
  { type: 'png', label: 'PNG image', mime: 'image/png', exts: ['png'], family: 'image', offset: 0, bytes: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a] },
  { type: 'jpeg', label: 'JPEG image', mime: 'image/jpeg', exts: ['jpg', 'jpeg'], family: 'image', offset: 0, bytes: [0xff, 0xd8, 0xff] },
  { type: 'gif', label: 'GIF image', mime: 'image/gif', exts: ['gif'], family: 'image', offset: 0, bytes: b('GIF8') },
  { type: 'bmp', label: 'BMP image', mime: 'image/bmp', exts: ['bmp'], family: 'image', offset: 0, bytes: b('BM') },
  { type: 'webp', label: 'WebP image', mime: 'image/webp', exts: ['webp'], family: 'image', offset: 0, bytes: b('RIFF'), also: { offset: 8, bytes: b('WEBP') } },
  { type: 'ico', label: 'Windows icon', mime: 'image/x-icon', exts: ['ico'], family: 'image', offset: 0, bytes: [0x00, 0x00, 0x01, 0x00] },
];

function matchesAt(buf: Uint8Array, offset: number, bytes: number[]): boolean {
  if (offset + bytes.length > buf.length) return false;
  for (let i = 0; i < bytes.length; i++) if (buf[offset + i] !== bytes[i]) return false;
  return true;
}

export function detectType(buf: Uint8Array): DetectedType | undefined {
  for (const sig of SIGNATURES) {
    if (matchesAt(buf, sig.offset, sig.bytes)) {
      if (sig.also && !matchesAt(buf, sig.also.offset, sig.also.bytes)) continue;
      const { offset, bytes, also, ...detected } = sig;
      void offset;
      void bytes;
      void also;
      return detected;
    }
  }

  if (matchesAt(buf, 0, b('#!'))) {
    return { type: 'script', label: 'Shell/interpreter script (shebang)', mime: 'text/x-shellscript', exts: ['sh', 'py', 'pl', 'rb'], family: 'script' };
  }
  return undefined;
}

export function extOf(filename: string): string {
  const dot = filename.lastIndexOf('.');
  if (dot <= 0 || dot === filename.length - 1) return '';
  return filename.slice(dot + 1).toLowerCase();
}

export interface MismatchResult {
  mismatch: boolean;
  detected?: DetectedType;
  declaredExt: string;

  executableMasquerade: boolean;
}

const BENIGN_FAMILIES = new Set(['document', 'image', 'media', 'other']);

export function checkTypeMismatch(buf: Uint8Array, filename: string): MismatchResult {
  const detected = detectType(buf);
  const declaredExt = extOf(filename);
  if (!detected) return { mismatch: false, declaredExt, executableMasquerade: false };

  const consistent = declaredExt === '' || detected.exts.includes(declaredExt);
  const mismatch = !consistent;

  const declaredFamily = familyForExt(declaredExt);
  const executableMasquerade =
    detected.family === 'executable' && declaredFamily !== undefined && BENIGN_FAMILIES.has(declaredFamily);
  return { mismatch, detected, declaredExt, executableMasquerade };
}

function familyForExt(ext: string): DetectedType['family'] | undefined {
  if (['exe', 'dll', 'sys', 'scr', 'com', 'msi', 'bat', 'cmd', 'jar', 'apk'].includes(ext)) return 'executable';
  if (['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'rtf', 'txt', 'odt'].includes(ext)) return 'document';
  if (['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'ico', 'svg'].includes(ext)) return 'image';
  if (['mp3', 'mp4', 'avi', 'mov', 'wav', 'mkv'].includes(ext)) return 'media';
  if (['zip', 'rar', '7z', 'gz', 'tar'].includes(ext)) return 'archive';
  if (['js', 'vbs', 'ps1', 'sh', 'py'].includes(ext)) return 'script';
  return ext === '' ? undefined : 'other';
}
