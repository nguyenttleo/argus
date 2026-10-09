

import { DatabaseSync } from 'node:sqlite';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import type { Report, ScanSummary, Stats, Verdict, ScanKind } from '@argus/shared';

const SCHEMA = `
CREATE TABLE IF NOT EXISTS scans (
  id            TEXT PRIMARY KEY,
  kind          TEXT NOT NULL,
  target        TEXT NOT NULL,
  verdict       TEXT NOT NULL,
  score         INTEGER NOT NULL,
  confidence    REAL NOT NULL,
  summary       TEXT NOT NULL,
  ip_hash       TEXT,
  created_at    TEXT NOT NULL,
  duration_ms   INTEGER,
  engine_version TEXT,
  report_json   TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS url_scans (
  scan_id TEXT PRIMARY KEY,
  url TEXT, final_url TEXT, registrable_domain TEXT, host TEXT
);
CREATE TABLE IF NOT EXISTS file_scans (
  scan_id TEXT PRIMARY KEY,
  sha256 TEXT, size INTEGER, real_type TEXT, declared_type TEXT
);
CREATE TABLE IF NOT EXISTS iocs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id TEXT NOT NULL,
  type TEXT NOT NULL,
  value TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_kind_created ON scans(kind, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_verdict_created ON scans(verdict, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_scans_kind_verdict_created ON scans(kind, verdict, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_file_sha ON file_scans(sha256);
`;

interface ScanRow {
  id: string;
  kind: string;
  target: string;
  verdict: string;
  score: number;
  confidence: number;
  summary: string;
  created_at: string;
  engine_version: string;
  report_json: string;
}

export class ArgusDb {
  #db: DatabaseSync;

  constructor(path: string) {
    if (path !== ':memory:') mkdirSync(dirname(path), { recursive: true });
    this.#db = new DatabaseSync(path);
    this.#db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA foreign_keys = ON;');
    this.#db.exec(SCHEMA);
  }

  insertReport(report: Report, ipHash?: string): void {
    this.#db.exec('BEGIN IMMEDIATE');
    try {
      const scanStmt = this.#db.prepare(
        `INSERT OR REPLACE INTO scans
          (id, kind, target, verdict, score, confidence, summary, ip_hash, created_at, duration_ms, engine_version, report_json)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?)`,
      );
      scanStmt.run(
        report.id,
        report.kind,
        report.target,
        report.verdict,
        report.score,
        report.confidence,
        report.summary,
        ipHash ?? null,
        report.createdAt,
        report.durationMs,
        report.engineVersion,
        JSON.stringify(report),
      );

      this.#db.prepare(`DELETE FROM url_scans WHERE scan_id = ?`).run(report.id);
      this.#db.prepare(`DELETE FROM file_scans WHERE scan_id = ?`).run(report.id);
      if (report.detail.kind === 'url') {
        const d = report.detail;
        this.#db
          .prepare(`INSERT OR REPLACE INTO url_scans (scan_id, url, final_url, registrable_domain, host) VALUES (?,?,?,?,?)`)
          .run(report.id, d.normalized, d.finalUrl ?? null, d.registrableDomain ?? null, d.host);
      } else {
        const d = report.detail;
        this.#db
          .prepare(`INSERT OR REPLACE INTO file_scans (scan_id, sha256, size, real_type, declared_type) VALUES (?,?,?,?,?)`)
          .run(report.id, d.sha256, d.size, d.realType ?? null, d.declaredType ?? null);
      }

      this.#db.prepare(`DELETE FROM iocs WHERE scan_id = ?`).run(report.id);
      const iocStmt = this.#db.prepare(`INSERT INTO iocs (scan_id, type, value) VALUES (?,?,?)`);
      for (const ioc of report.iocs) iocStmt.run(report.id, ioc.type, ioc.value);
      this.#db.exec('COMMIT');
    } catch (e) {
      try {
        this.#db.exec('ROLLBACK');
      } catch {}
      throw e;
    }
  }

  getReport(id: string): Report | undefined {
    const row = this.#db.prepare(`SELECT report_json FROM scans WHERE id = ?`).get(id) as unknown as
      | { report_json: string }
      | undefined;
    return row ? (JSON.parse(row.report_json) as Report) : undefined;
  }

  listScans(opts: { limit?: number; offset?: number; kind?: ScanKind; verdict?: Verdict } = {}): ScanSummary[] {
    const limit = Math.min(Math.max(opts.limit ?? 50, 1), 200);
    const offset = Math.max(opts.offset ?? 0, 0);
    const where: string[] = [];
    const params: string[] = [];
    if (opts.kind) {
      where.push('kind = ?');
      params.push(opts.kind);
    }
    if (opts.verdict) {
      where.push('verdict = ?');
      params.push(opts.verdict);
    }
    const sql = `SELECT id, kind, target, verdict, score, confidence, summary, created_at, engine_version
                 FROM scans ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
                 ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    const rows = this.#db.prepare(sql).all(...params, limit, offset) as unknown as ScanRow[];
    return rows.map(rowToSummary);
  }

  searchByIoc(value: string): ScanSummary[] {
    const ids = this.#db.prepare(`SELECT DISTINCT scan_id FROM iocs WHERE value = ? LIMIT 100`).all(value) as unknown as {
      scan_id: string;
    }[];
    if (ids.length === 0) return [];
    const placeholders = ids.map(() => '?').join(',');
    const rows = this.#db
      .prepare(
        `SELECT id, kind, target, verdict, score, confidence, summary, created_at, engine_version
         FROM scans WHERE id IN (${placeholders}) ORDER BY created_at DESC`,
      )
      .all(...ids.map((r) => r.scan_id)) as unknown as ScanRow[];
    return rows.map(rowToSummary);
  }

  stats(): Stats {
    const total = (this.#db.prepare(`SELECT COUNT(*) c FROM scans`).get() as unknown as { c: number }).c;
    const byVerdict: Record<Verdict, number> = { safe: 0, suspicious: 0, malicious: 0 };
    for (const r of this.#db.prepare(`SELECT verdict, COUNT(*) c FROM scans GROUP BY verdict`).all() as unknown as {
      verdict: Verdict;
      c: number;
    }[]) {
      byVerdict[r.verdict] = r.c;
    }
    const byKind: Record<ScanKind, number> = { url: 0, file: 0 };
    for (const r of this.#db.prepare(`SELECT kind, COUNT(*) c FROM scans GROUP BY kind`).all() as unknown as {
      kind: ScanKind;
      c: number;
    }[]) {
      byKind[r.kind] = r.c;
    }
    return { total, byVerdict, byKind };
  }

  close(): void {
    this.#db.close();
  }
}

function rowToSummary(r: ScanRow): ScanSummary {
  return {
    id: r.id,
    kind: r.kind as ScanKind,
    target: r.target,
    verdict: r.verdict as Verdict,
    score: r.score,
    confidence: r.confidence,
    summary: r.summary,
    createdAt: r.created_at,
    engineVersion: r.engine_version,
  };
}
