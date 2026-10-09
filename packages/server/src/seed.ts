

import { analyzeFile, analyzeUrl } from '@argus/engine';
import { ArgusDb } from './db.ts';
import { loadServerConfig } from './config.ts';

const EICAR = Buffer.from(
  'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=',
  'base64',
);
const WEBSHELL = '<' + '?php @' + 'eval($' + '_POST["c"]); ' + 'system($' + '_GET["x"]); ?>';
const enc = (s: string) => new TextEncoder().encode(s);
const masqueradeExe = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, ...enc('PE not pdf VirtualAllocEx WriteProcessMemory CreateRemoteThread')]);

export async function seed(db: ArgusDb): Promise<number> {
  const reports = await Promise.all([
    analyzeUrl('https://www.google.com/search?q=hello', { reputation: true }),
    analyzeUrl('http://paypal.com@secure-paypa1-login.tk/webscr?cmd=verify', { reputation: true }),
    analyzeUrl('https://bit.ly/3xExample', {}),
    analyzeFile({ filename: 'eicar.com', bytes: new Uint8Array(EICAR) }, { reputation: true }),
    analyzeFile({ filename: 'q3-report.txt', bytes: enc('Quarterly numbers look healthy. See attached spreadsheet.') }, {}),
    analyzeFile({ filename: 'invoice.pdf', bytes: masqueradeExe }, {}),
    analyzeFile({ filename: 'update.php', bytes: enc(WEBSHELL) }, {}),
  ]);
  for (const r of reports) db.insertReport(r, 'seed');
  return reports.length;
}


if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('seed.ts')) {
  const config = loadServerConfig();
  const db = new ArgusDb(config.dbPath);
  const n = await seed(db);
  console.log(`Seeded ${n} demo scans into ${config.dbPath}`);
  db.close();
}
