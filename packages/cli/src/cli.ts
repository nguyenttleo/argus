#!/usr/bin/env node

import { readFileSync } from 'node:fs';
import { basename } from 'node:path';
import { analyzeUrl, analyzeFile, InvalidUrlError } from '@argus/engine';
import type { Report } from '@argus/shared';
import { renderReport, exitCodeFor } from './render.ts';

const HELP = `
Argus - URL & file threat scanner

Usage:
  argus url  <url>   [--no-fetch] [--no-reputation] [--json]
  argus file <path>  [--no-reputation] [--detonate]    [--json]
  argus demo                                            [--json]

Options:
  --no-fetch         URL: skip SSRF-safe redirect/content fetch (lexical only)
  --no-reputation    skip external reputation feeds (heuristics/signatures only)
  --detonate         file: detonate py/js in Tartarus if TARTARUS_URL is set
  --json             print the raw Report as JSON
  -h, --help         this help

Exit codes: 0 safe · 1 suspicious · 2 malicious · 3 error
`;

interface Flags {
  json: boolean;
  noFetch: boolean;
  noReputation: boolean;
  detonate: boolean;
}

function parseFlags(args: string[]): { positionals: string[]; flags: Flags } {
  const positionals: string[] = [];
  const flags: Flags = { json: false, noFetch: false, noReputation: false, detonate: false };
  for (const a of args) {
    if (a === '--json') flags.json = true;
    else if (a === '--no-fetch') flags.noFetch = true;
    else if (a === '--no-reputation') flags.noReputation = true;
    else if (a === '--detonate') flags.detonate = true;
    else positionals.push(a);
  }
  return { positionals, flags };
}

function output(report: Report, flags: Flags): void {
  if (flags.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    process.stdout.write(renderReport(report, { color: process.stdout.isTTY === true && !process.env.NO_COLOR }));
  }
}

async function main(): Promise<number> {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === '-h' || argv[0] === '--help') {
    process.stdout.write(HELP);
    return argv.length === 0 ? 3 : 0;
  }

  const cmd = argv[0];
  const { positionals, flags } = parseFlags(argv.slice(1));

  if (cmd === 'url') {
    const url = positionals[0];
    if (!url) {
      process.stderr.write('error: missing <url>\n');
      return 3;
    }
    try {
      const report = await analyzeUrl(url, { fetch: !flags.noFetch, reputation: !flags.noReputation });
      output(report, flags);
      return exitCodeFor(report.verdict);
    } catch (e) {
      if (e instanceof InvalidUrlError) {
        process.stderr.write(`error: ${e.message}\n`);
        return 3;
      }
      throw e;
    }
  }

  if (cmd === 'file') {
    const path = positionals[0];
    if (!path) {
      process.stderr.write('error: missing <path>\n');
      return 3;
    }
    let bytes: Buffer;
    try {
      bytes = readFileSync(path);
    } catch (e) {
      process.stderr.write(`error: cannot read "${path}": ${(e as Error).message}\n`);
      return 3;
    }
    const report = await analyzeFile(
      { filename: basename(path), bytes: new Uint8Array(bytes) },
      { reputation: !flags.noReputation, detonate: flags.detonate },
    );
    output(report, flags);
    return exitCodeFor(report.verdict);
  }

  if (cmd === 'demo') {
    return runDemo(flags);
  }

  process.stderr.write(`error: unknown command "${cmd}"\n${HELP}`);
  return 3;
}

const EICAR = Buffer.from(
  'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=',
  'base64',
);

async function runDemo(flags: Flags): Promise<number> {
  if (!flags.json) {
    process.stdout.write('\n  Running the safe demo: a benign URL, a phishing URL, and the EICAR test file.\n');
  }
  const reports = [
    await analyzeUrl('https://www.google.com/', { reputation: true }),
    await analyzeUrl('http://paypal.com@secure-paypa1-login.tk/webscr?cmd=verify', { reputation: true }),
    await analyzeFile({ filename: 'eicar.com', bytes: new Uint8Array(EICAR) }, { reputation: true }),
  ];
  if (flags.json) {
    process.stdout.write(JSON.stringify(reports, null, 2) + '\n');
  } else {
    for (const r of reports) process.stdout.write(renderReport(r, { color: process.stdout.isTTY === true && !process.env.NO_COLOR }));
  }
  return 0;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    process.stderr.write(`fatal: ${err?.stack ?? err}\n`);
    process.exit(3);
  });
