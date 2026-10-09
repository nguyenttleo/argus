



export interface YaraStringDef {
  id: string;
  kind: 'text' | 'hex' | 'regex';
  source: string;
  nocase: boolean;
  wide: boolean;
  ascii: boolean;
  fullword: boolean;

  hex?: HexPart[];

  re?: RegExp;
}

type HexPart = { kind: 'bytes'; bytes: (number | null)[] } | { kind: 'jump'; min: number; max: number };

export interface YaraRule {
  name: string;
  tags: string[];
  meta: Record<string, string | number | boolean>;
  strings: YaraStringDef[];
  conditionSrc: string;
  ast: Node;
}

export interface YaraMatch {
  rule: string;
  tags: string[];
  meta: Record<string, string | number | boolean>;
  strings: string[];
}

export interface ParseResult {
  rules: YaraRule[];
  errors: string[];
}




function stripComments(src: string): string {
  let out = '';
  let i = 0;
  while (i < src.length) {
    const c = src[i]!;
    const d = src[i + 1];
    if (c === '"') {
      out += c;
      i++;
      while (i < src.length && src[i] !== '"') {
        if (src[i] === '\\') {
          out += src[i];
          i++;
        }
        if (i < src.length) {
          out += src[i];
          i++;
        }
      }
      if (i < src.length) {
        out += src[i];
        i++;
      }
      continue;
    }
    if (c === '/' && d === '/') {
      while (i < src.length && src[i] !== '\n') i++;
      continue;
    }
    if (c === '/' && d === '*') {
      i += 2;
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    if (c === '/') {

      out += c;
      i++;
      while (i < src.length && src[i] !== '/' && src[i] !== '\n') {
        if (src[i] === '\\') {
          out += src[i];
          i++;
        }
        if (i < src.length) {
          out += src[i];
          i++;
        }
      }
      if (i < src.length) {
        out += src[i];
        i++;
      }
      continue;
    }
    out += c;
    i++;
  }
  return out;
}

export function parseYaraRules(input: string): ParseResult {
  const src = stripComments(input);
  const rules: YaraRule[] = [];
  const errors: string[] = [];
  const ruleRe = /\brule\s+([A-Za-z_]\w*)\s*(?::\s*([\w\s]+?))?\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = ruleRe.exec(src)) !== null) {
    const name = m[1]!;
    const tags = (m[2]?.trim().split(/\s+/).filter(Boolean)) ?? [];
    const bodyStart = ruleRe.lastIndex;
    const end = matchBrace(src, bodyStart - 1);
    if (end < 0) {
      errors.push(`rule ${name}: unbalanced braces`);
      continue;
    }
    const body = src.slice(bodyStart, end);
    try {
      rules.push(parseRuleBody(name, tags, body));
    } catch (e) {
      errors.push(`rule ${name}: ${(e as Error).message}`);
    }
    ruleRe.lastIndex = end + 1;
  }
  return { rules, errors };
}


function matchBrace(src: string, openIdx: number): number {
  let depth = 0;
  let i = openIdx;
  while (i < src.length) {
    const c = src[i]!;
    if (c === '"') {
      i++;
      while (i < src.length && src[i] !== '"') {
        if (src[i] === '\\') i++;
        i++;
      }
      i++;
      continue;
    }
    if (c === '/') {

      i++;
      while (i < src.length && src[i] !== '/' && src[i] !== '\n') {
        if (src[i] === '\\') i++;
        i++;
      }
      i++;
      continue;
    }
    if (c === '{') depth++;
    else if (c === '}') {
      depth--;
      if (depth === 0) return i;
    }
    i++;
  }
  return -1;
}

function parseRuleBody(name: string, tags: string[], body: string): YaraRule {
  const meta: Record<string, string | number | boolean> = {};
  const strings: YaraStringDef[] = [];

  const metaM = /\bmeta\s*:([\s\S]*?)(?=\bstrings\s*:|\bcondition\s*:|$)/.exec(body);
  if (metaM) {
    const re = /([A-Za-z_]\w*)\s*=\s*("(?:[^"\\]|\\.)*"|true|false|-?\d+)/g;
    let mm: RegExpExecArray | null;
    while ((mm = re.exec(metaM[1]!)) !== null) {
      const key = mm[1]!;
      const raw = mm[2]!;
      meta[key] =
        raw === 'true' ? true : raw === 'false' ? false : raw.startsWith('"') ? JSON.parse(raw) : Number(raw);
    }
  }

  const strM = /\bstrings\s*:([\s\S]*?)(?=\bcondition\s*:|$)/.exec(body);
  if (strM) {
    const re = /(\$[A-Za-z0-9_]*)\s*=\s*(?:"((?:[^"\\]|\\.)*)"|\{([^}]*)\}|\/((?:[^/\\]|\\.)+)\/)([a-z\s]*)/g;
    let sm: RegExpExecArray | null;
    while ((sm = re.exec(strM[1]!)) !== null) {
      const id = sm[1]!;
      const mods = (sm[5] ?? '').toLowerCase();
      const def: YaraStringDef = {
        id,
        kind: sm[2] !== undefined ? 'text' : sm[3] !== undefined ? 'hex' : 'regex',
        source: sm[2] ?? sm[3] ?? sm[4] ?? '',
        nocase: /\bnocase\b/.test(mods),
        wide: /\bwide\b/.test(mods),
        ascii: /\bascii\b/.test(mods),
        fullword: /\bfullword\b/.test(mods),
      };
      if (def.kind === 'hex') def.hex = parseHex(def.source);
      if (def.kind === 'regex') def.re = new RegExp(unescapeYaraString(def.source), def.nocase ? 'gi' : 'g');
      if (def.kind === 'text') def.source = unescapeYaraString(sm[2]!);
      strings.push(def);
    }
  }

  const condM = /\bcondition\s*:([\s\S]*)$/.exec(body);
  if (!condM) throw new Error('missing condition');
  const conditionSrc = condM[1]!.trim();
  const ast = parseCondition(conditionSrc);
  return { name, tags, meta, strings, conditionSrc, ast };
}

function unescapeYaraString(s: string): string {
  return s.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/\\n/g, '\n')
    .replace(/\\r/g, '\r')
    .replace(/\\t/g, '\t')
    .replace(/\\"/g, '"')
    .replace(/\\\\/g, '\\');
}

function parseHex(src: string): HexPart[] {
  const parts: HexPart[] = [];
  let bytes: (number | null)[] = [];
  const flush = () => {
    if (bytes.length) {
      parts.push({ kind: 'bytes', bytes });
      bytes = [];
    }
  };
  const tokens = src.trim().split(/\s+/).filter(Boolean);
  for (const tRaw of tokens) {
    let t = tRaw;

    const jump = /^\[(\d*)(?:-(\d*))?\]$/.exec(t);
    if (jump) {
      flush();
      const min = jump[1] ? Number(jump[1]) : 0;
      const max = jump[2] !== undefined ? (jump[2] ? Number(jump[2]) : 0xffff) : jump[1] ? Number(jump[1]) : 0xffff;
      parts.push({ kind: 'jump', min, max });
      continue;
    }

    while (t.length >= 2) {
      const pair = t.slice(0, 2);
      t = t.slice(2);
      if (pair === '??') bytes.push(null);
      else {
        const v = parseInt(pair.replace(/\?/g, '0'), 16);
        if (Number.isNaN(v)) throw new Error(`bad hex token "${pair}"`);
        bytes.push(pair.includes('?') ? null : v);
      }
    }
    if (t.length) throw new Error(`odd hex nibble "${tRaw}"`);
  }
  flush();
  return parts;
}



type Node =
  | { t: 'num'; v: number }
  | { t: 'str'; id: string }
  | { t: 'count'; id: string }
  | { t: 'offset'; id: string }
  | { t: 'at'; id: string; expr: Node }
  | { t: 'ident'; name: string }
  | { t: 'call'; name: string; arg: Node }
  | { t: 'unary'; op: string; e: Node }
  | { t: 'bin'; op: string; l: Node; r: Node }
  | { t: 'of'; quant: { kind: 'any' | 'all' | 'num'; n?: number }; set: { them: true } | { ids: string[] } };

interface Tok {
  type: 'num' | 'id' | 'str' | 'count' | 'offset' | 'op' | 'kw';
  v: string;
  n?: number;
}

const KEYWORDS = new Set(['and', 'or', 'not', 'of', 'them', 'all', 'any', 'at', 'true', 'false']);

function tokenizeCondition(src: string): Tok[] {
  const toks: Tok[] = [];
  let i = 0;
  const isIdent = (c: string) => /[A-Za-z0-9_]/.test(c);
  while (i < src.length) {
    const c = src[i]!;
    if (/\s/.test(c)) {
      i++;
      continue;
    }
    if (c === '$' || c === '#' || c === '@') {
      let j = i + 1;
      while (j < src.length && (isIdent(src[j]!) || src[j] === '*')) j++;
      const v = src.slice(i, j);
      toks.push({ type: c === '$' ? 'str' : c === '#' ? 'count' : 'offset', v });
      i = j;
      continue;
    }
    if (/[0-9]/.test(c)) {
      let j = i;
      if (src.slice(i, i + 2).toLowerCase() === '0x') {
        j = i + 2;
        while (j < src.length && /[0-9a-fA-F]/.test(src[j]!)) j++;
        toks.push({ type: 'num', v: src.slice(i, j), n: parseInt(src.slice(i, j), 16) });
      } else {
        while (j < src.length && /[0-9]/.test(src[j]!)) j++;
        let mult = 1;
        const suffix = src.slice(j, j + 2).toUpperCase();
        if (suffix === 'KB') {
          mult = 1024;
          j += 2;
        } else if (suffix === 'MB') {
          mult = 1024 * 1024;
          j += 2;
        }
        toks.push({ type: 'num', v: src.slice(i, j), n: parseInt(src.slice(i, j), 10) * mult });
      }
      i = j;
      continue;
    }
    if (isIdent(c)) {
      let j = i;
      while (j < src.length && isIdent(src[j]!)) j++;
      const word = src.slice(i, j);
      toks.push({ type: KEYWORDS.has(word.toLowerCase()) ? 'kw' : 'id', v: word });
      i = j;
      continue;
    }

    const two = src.slice(i, i + 2);
    if (['==', '!=', '<=', '>='].includes(two)) {
      toks.push({ type: 'op', v: two });
      i += 2;
      continue;
    }
    if ('()<>+-*%,'.includes(c)) {
      toks.push({ type: 'op', v: c });
      i++;
      continue;
    }
    throw new Error(`unexpected character "${c}" in condition`);
  }
  return toks;
}

function parseCondition(src: string): Node {
  const toks = tokenizeCondition(src);
  let pos = 0;
  const peek = () => toks[pos];
  const next = () => toks[pos++];
  const expect = (v: string) => {
    const t = next();
    if (!t || t.v !== v) throw new Error(`expected "${v}" but got "${t?.v ?? 'EOF'}"`);
  };


  const BIN_PREC: Record<string, number> = {
    or: 1, and: 2, '==': 3, '!=': 3, '<': 3, '<=': 3, '>': 3, '>=': 3, '+': 4, '-': 4, '*': 5, '%': 5,
  };

  function parseExpr(minPrec: number): Node {
    let left = parseUnary();
    for (;;) {
      const t = peek();
      if (!t) break;
      const op = t.type === 'kw' ? t.v.toLowerCase() : t.v;
      const prec = BIN_PREC[op];
      if (prec === undefined || prec < minPrec) break;
      next();
      const right = parseExpr(prec + 1);
      left = { t: 'bin', op, l: left, r: right };
    }
    return left;
  }

  function parseUnary(): Node {
    const t = peek();
    if (t && ((t.type === 'kw' && t.v.toLowerCase() === 'not') || (t.type === 'op' && t.v === '-'))) {
      next();
      return { t: 'unary', op: t.v.toLowerCase(), e: parseUnary() };
    }
    return parsePostfix();
  }

  function parsePostfix(): Node {
    let node = parsePrimary();

    const t = peek();
    if (node.t === 'str' && t && t.type === 'kw' && t.v.toLowerCase() === 'at') {
      next();
      node = { t: 'at', id: node.id, expr: parseExpr(4) };
    }
    return node;
  }

  function parseSet(): { them: true } | { ids: string[] } {
    const t = peek();
    if (t && t.type === 'kw' && t.v.toLowerCase() === 'them') {
      next();
      return { them: true };
    }
    expect('(');
    const ids: string[] = [];
    for (;;) {
      const s = next();
      if (!s || s.type !== 'str') throw new Error('expected string id in set');
      ids.push(s.v);
      const sep = peek();
      if (sep && sep.type === 'op' && sep.v === ',') {
        next();
        continue;
      }
      break;
    }
    expect(')');
    return { ids };
  }

  function parsePrimary(): Node {
    const t = next();
    if (!t) throw new Error('unexpected end of condition');

    if (t.type === 'kw') {
      const kw = t.v.toLowerCase();
      if (kw === 'any' || kw === 'all') {
        expect('of');
        return { t: 'of', quant: { kind: kw }, set: parseSet() };
      }
      if (kw === 'true') return { t: 'num', v: 1 };
      if (kw === 'false') return { t: 'num', v: 0 };
      throw new Error(`unexpected keyword "${t.v}"`);
    }
    if (t.type === 'num') {

      const la = peek();
      if (la && la.type === 'kw' && la.v.toLowerCase() === 'of') {
        next();
        return { t: 'of', quant: { kind: 'num', n: t.n! }, set: parseSet() };
      }
      return { t: 'num', v: t.n! };
    }
    if (t.type === 'str') return { t: 'str', id: t.v };
    if (t.type === 'count') return { t: 'count', id: '$' + t.v.slice(1) };
    if (t.type === 'offset') return { t: 'offset', id: '$' + t.v.slice(1) };
    if (t.type === 'op' && t.v === '(') {
      const e = parseExpr(0);
      expect(')');
      return e;
    }
    if (t.type === 'id') {
      const la = peek();
      if (la && la.type === 'op' && la.v === '(') {
        next();
        const arg = parseExpr(0);
        expect(')');
        return { t: 'call', name: t.v, arg };
      }
      return { t: 'ident', name: t.v };
    }
    throw new Error(`unexpected token "${t.v}"`);
  }

  const ast = parseExpr(0);
  if (pos < toks.length) throw new Error(`trailing tokens in condition near "${toks[pos]?.v}"`);
  return ast;
}



interface ScanCtx {
  buf: Uint8Array;
  latin1: string;
  matches: Map<string, number[]>;
}

function buildContext(buf: Uint8Array, latin1: string, rule: YaraRule): ScanCtx {
  const matches = new Map<string, number[]>();
  for (const s of rule.strings) matches.set(s.id, findString(buf, latin1, s));
  return { buf, latin1, matches };
}

function findString(buf: Uint8Array, latin1: string, s: YaraStringDef): number[] {
  if (s.kind === 'text') return findText(latin1, s.source, s);
  if (s.kind === 'hex') return findHex(buf, s.hex!);
  return findRegex(latin1, s.re!);
}

function findText(hay: string, needle: string, s: YaraStringDef): number[] {
  const offsets: number[] = [];
  const wantWide = s.wide;
  const wantAscii = s.ascii || !s.wide;
  const variants: string[] = [];
  if (wantAscii) variants.push(needle);
  if (wantWide) variants.push([...needle].map((c) => c + '\x00').join(''));
  for (const v of variants) {
    const h = s.nocase ? hay.toLowerCase() : hay;
    const n = s.nocase ? v.toLowerCase() : v;
    let idx = h.indexOf(n);
    while (idx !== -1) {
      if (!s.fullword || isFullword(hay, idx, n.length)) offsets.push(idx);
      idx = h.indexOf(n, idx + 1);
    }
  }
  return offsets.sort((a, b) => a - b);
}

function isFullword(hay: string, idx: number, len: number): boolean {
  const before = idx > 0 ? hay[idx - 1]! : ' ';
  const after = idx + len < hay.length ? hay[idx + len]! : ' ';
  return !/[A-Za-z0-9_]/.test(before) && !/[A-Za-z0-9_]/.test(after);
}

function findRegex(hay: string, re: RegExp): number[] {
  const offsets: number[] = [];
  re.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = re.exec(hay)) !== null) {
    offsets.push(m.index);
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  return offsets;
}

function findHex(buf: Uint8Array, parts: HexPart[]): number[] {
  const offsets: number[] = [];
  for (let start = 0; start < buf.length; start++) {
    if (matchHexAt(buf, start, parts, 0)) offsets.push(start);
  }
  return offsets;
}

function matchHexAt(buf: Uint8Array, pos: number, parts: HexPart[], pi: number): boolean {
  if (pi >= parts.length) return true;
  const part = parts[pi]!;
  if (part.kind === 'bytes') {
    if (pos + part.bytes.length > buf.length) return false;
    for (let k = 0; k < part.bytes.length; k++) {
      const want = part.bytes[k];
      if (want !== null && buf[pos + k] !== want) return false;
    }
    return matchHexAt(buf, pos + part.bytes.length, parts, pi + 1);
  }

  const max = Math.min(part.max, buf.length - pos);
  for (let adv = part.min; adv <= max; adv++) {
    if (matchHexAt(buf, pos + adv, parts, pi + 1)) return true;
  }
  return false;
}



function readUint(buf: Uint8Array, off: number, size: number): number {
  if (off < 0 || off + size > buf.length) return 0;
  let v = 0;
  for (let i = 0; i < size; i++) v |= buf[off + i]! << (8 * i);
  return v >>> 0;
}

function evalNode(node: Node, ctx: ScanCtx, rule: YaraRule): number {
  switch (node.t) {
    case 'num':
      return node.v;
    case 'ident':
      if (node.name === 'filesize') return ctx.buf.length;
      if (node.name === 'entrypoint') return 0;
      return 0;
    case 'str':
      return (ctx.matches.get(node.id)?.length ?? 0) > 0 ? 1 : 0;
    case 'count':
      return ctx.matches.get(node.id)?.length ?? 0;
    case 'offset':
      return ctx.matches.get(node.id)?.[0] ?? -1;
    case 'at': {
      const want = evalNode(node.expr, ctx, rule);
      return ctx.matches.get(node.id)?.includes(want) ? 1 : 0;
    }
    case 'call': {
      const off = evalNode(node.arg, ctx, rule);
      const size = node.name.includes('8') ? 1 : node.name.includes('16') ? 2 : 4;
      return readUint(ctx.buf, off, size);
    }
    case 'unary':
      if (node.op === 'not') return evalNode(node.e, ctx, rule) ? 0 : 1;
      return -evalNode(node.e, ctx, rule);
    case 'bin':
      return evalBin(node, ctx, rule);
    case 'of':
      return evalOf(node, ctx, rule);
  }
}

function evalBin(node: Extract<Node, { t: 'bin' }>, ctx: ScanCtx, rule: YaraRule): number {
  const l = evalNode(node.l, ctx, rule);
  const r = evalNode(node.r, ctx, rule);
  switch (node.op) {
    case 'and':
      return l && r ? 1 : 0;
    case 'or':
      return l || r ? 1 : 0;
    case '==':
      return l === r ? 1 : 0;
    case '!=':
      return l !== r ? 1 : 0;
    case '<':
      return l < r ? 1 : 0;
    case '<=':
      return l <= r ? 1 : 0;
    case '>':
      return l > r ? 1 : 0;
    case '>=':
      return l >= r ? 1 : 0;
    case '+':
      return l + r;
    case '-':
      return l - r;
    case '*':
      return l * r;
    case '%':
      return r === 0 ? 0 : l % r;
    default:
      return 0;
  }
}

function expandSet(set: { them: true } | { ids: string[] }, rule: YaraRule): string[] {
  const all = rule.strings.map((s) => s.id);
  if ('them' in set) return all;
  const out: string[] = [];
  for (const id of set.ids) {
    if (id.endsWith('*')) {
      const prefix = id.slice(0, -1);
      out.push(...all.filter((a) => a.startsWith(prefix)));
    } else if (all.includes(id)) {
      out.push(id);
    }
  }
  return out;
}

function evalOf(node: Extract<Node, { t: 'of' }>, ctx: ScanCtx, rule: YaraRule): number {
  const ids = expandSet(node.set, rule);
  const matched = ids.filter((id) => (ctx.matches.get(id)?.length ?? 0) > 0).length;
  const need =
    node.quant.kind === 'any' ? 1 : node.quant.kind === 'all' ? ids.length : (node.quant.n ?? 0);
  return matched >= need && ids.length > 0 ? 1 : 0;
}



export function scanBytes(buf: Uint8Array, rules: YaraRule[]): YaraMatch[] {
  const out: YaraMatch[] = [];


  const latin1 = Buffer.from(buf).toString('latin1');
  for (const rule of rules) {
    let ctx: ScanCtx;
    try {
      ctx = buildContext(buf, latin1, rule);
      if (evalNode(rule.ast, ctx, rule)) {
        const matchedStrings = rule.strings.filter((s) => (ctx.matches.get(s.id)?.length ?? 0) > 0).map((s) => s.id);
        out.push({ rule: rule.name, tags: rule.tags, meta: rule.meta, strings: matchedStrings });
      }
    } catch {
      // Skip rules that fail to evaluate.
    }
  }
  return out;
}

export function compileAndScan(ruleText: string, buf: Uint8Array): { matches: YaraMatch[]; errors: string[] } {
  const { rules, errors } = parseYaraRules(ruleText);
  return { matches: scanBytes(buf, rules), errors };
}
