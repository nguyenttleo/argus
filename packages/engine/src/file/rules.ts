import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseYaraRules, type YaraRule } from './yara.ts';

/** Load + cache the bundled YARA rules (and any extra rule paths). */
let cached: { rules: YaraRule[]; errors: string[] } | undefined;

const BUILTIN = fileURLToPath(new URL('../../rules/builtin.yar', import.meta.url));

export function loadBuiltinRules(extraPaths: string[] = []): { rules: YaraRule[]; errors: string[] } {
  if (cached && extraPaths.length === 0) return cached;
  const errors: string[] = [];
  let text = '';
  for (const p of [BUILTIN, ...extraPaths]) {
    try {
      if (existsSync(p)) text += '\n' + readFileSync(p, 'utf8');
      else errors.push(`rule file not found: ${p}`);
    } catch (e) {
      errors.push(`failed reading ${p}: ${(e as Error).message}`);
    }
  }
  const parsed = parseYaraRules(text);
  const result = { rules: parsed.rules, errors: [...errors, ...parsed.errors] };
  if (extraPaths.length === 0) cached = result;
  return result;
}
