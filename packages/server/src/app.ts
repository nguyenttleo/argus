/**
 * Argus REST API (Fastify). Validates + rate-limits input, runs the shared analysis
 * engines, persists results to SQLite, and (optionally) quarantines uploaded bytes.
 *
 * The server is the trust boundary: it treats every input as hostile, never executes
 * uploads, fetches URLs only through the SSRF-safe fetcher, and never re-serves a
 * quarantined sample.
 */

import { createHmac } from 'node:crypto';
import { mkdirSync } from 'node:fs';
import Fastify, { type FastifyInstance } from 'fastify';
import cors from '@fastify/cors';
import multipart from '@fastify/multipart';
import rateLimit from '@fastify/rate-limit';
import {
  analyzeFile,
  analyzeUrl,
  createReputationRegistry,
  InvalidUrlError,
  loadBuiltinRules,
  hashBytes,
  TtlCache,
} from '@argus/engine';
import type { Report } from '@argus/shared';
import { ArgusDb } from './db.ts';
import { Quarantine, resolveQuarantineKey } from './quarantine.ts';
import type { ServerConfig } from './config.ts';

export interface AppDeps {
  db?: ArgusDb;
  quarantine?: Quarantine | null;
}

export async function buildApp(config: ServerConfig, deps: AppDeps = {}): Promise<FastifyInstance> {
  mkdirSync(config.dataDir, { recursive: true });

  const app = Fastify({
    logger: false,
    bodyLimit: 1 * 1024 * 1024, // JSON body cap (file uploads go through multipart)
    trustProxy: true,
  });

  const db = deps.db ?? new ArgusDb(config.dbPath);
  const registry = createReputationRegistry(config);
  const rules = loadBuiltinRules().rules;
  // Full-scan result cache: an identical request within the TTL returns instantly
  // instead of re-fetching/re-hashing (efficiency). Bypass with `fresh: true`.
  const scanCache = new TtlCache<Report>();
  const quarantine =
    deps.quarantine !== undefined
      ? deps.quarantine
      : config.quarantineEnabled
        ? new Quarantine({
            dir: `${config.dataDir}/quarantine`,
            key: resolveQuarantineKey(config.dataDir, config.ipHashSecret),
            ttlMs: config.quarantineTtlMs,
          })
        : null;

  const hashIp = (ip: string): string =>
    createHmac('sha256', config.ipHashSecret).update(ip).digest('hex').slice(0, 32);

  // Periodic TTL sweep of the quarantine bucket.
  if (quarantine) {
    const timer = setInterval(() => {
      try {
        quarantine.sweep();
      } catch {
        /* best-effort */
      }
    }, 60 * 60 * 1000);
    timer.unref();
    app.addHook('onClose', async () => clearInterval(timer));
  }

  await app.register(cors, { origin: config.corsOrigin === '*' ? true : config.corsOrigin.split(',') });
  // throwFileSizeLimit:false → an oversize upload yields a truncated buffer with
  // `file.truncated === true` (handled as a clean 413) instead of throwing.
  await app.register(multipart, {
    limits: { fileSize: config.maxUploadBytes, files: 1 },
    throwFileSizeLimit: false,
  });
  await app.register(rateLimit, {
    global: false,
    max: config.rateLimitMax,
    timeWindow: config.rateLimitWindowMs,
    keyGenerator: (req) => req.ip,
  });
  const scanRateLimit = app.rateLimit({
    max: config.rateLimitMax,
    timeWindow: config.rateLimitWindowMs,
    groupId: 'scan',
  });

  app.setErrorHandler((err: { statusCode?: number; message?: string }, _req, reply) => {
    const status = err.statusCode ?? 500;
    if (status === 429) {
      return reply.status(429).send({ error: 'rate_limited', message: 'Too many requests - slow down.' });
    }
    reply.status(status >= 400 && status < 600 ? status : 500).send({
      error: 'internal_error',
      message: status >= 500 ? 'Internal error' : (err.message ?? 'Error'),
    });
  });

  // ── health / index ──
  app.get('/api/health', async () => ({
    status: 'ok',
    service: 'argus',
    engineVersion: '1.0.0',
    rulesLoaded: rules.length,
    reputationProviders: registry.configuredProviders(),
    quarantine: quarantine ? 'enabled' : 'hash-only',
  }));

  app.get('/', async () => ({
    service: 'Argus - URL & File Threat Scanner',
    endpoints: [
      'POST /api/scan/url   {url, fetch?, reputation?}',
      'POST /api/scan/file  (multipart: file)',
      'GET  /api/scan/:id',
      'GET  /api/scans?limit&offset&kind&verdict',
      'GET  /api/stats',
      'GET  /api/iocs/:value',
      'GET  /api/health',
    ],
  }));

  // ── URL scan ──
  app.post('/api/scan/url', { preHandler: scanRateLimit }, async (req, reply) => {
    const body = (req.body ?? {}) as { url?: unknown; fetch?: unknown; reputation?: unknown; fresh?: unknown };
    if (typeof body.url !== 'string' || body.url.trim() === '') {
      return reply.status(400).send({ error: 'bad_request', message: 'Provide a "url" string.' });
    }
    if (body.url.length > 4096) {
      return reply.status(400).send({ error: 'bad_request', message: 'URL too long.' });
    }
    const opts = {
      fetch: typeof body.fetch === 'boolean' ? body.fetch : config.urlFetchDefault,
      reputation: typeof body.reputation === 'boolean' ? body.reputation : config.reputationDefault,
    };
    const cacheKey = `u:${body.url}:${opts.fetch}:${opts.reputation}`;
    if (body.fresh !== true) {
      const cached = scanCache.get(cacheKey);
      if (cached) return cached;
    }
    let report: Report;
    try {
      report = await analyzeUrl(body.url, opts, { config, registry });
    } catch (e) {
      if (e instanceof InvalidUrlError) {
        return reply.status(400).send({ error: 'invalid_url', message: e.message });
      }
      throw e;
    }
    scanCache.set(cacheKey, report, config.scanCacheTtlMs);
    db.insertReport(report, hashIp(req.ip));
    return report;
  });

  // ── File scan ──
  app.post('/api/scan/file', { preHandler: scanRateLimit }, async (req, reply) => {
    let data;
    try {
      data = await req.file();
    } catch {
      return reply.status(400).send({ error: 'bad_request', message: 'Expected a multipart file upload.' });
    }
    if (!data) {
      return reply.status(400).send({ error: 'bad_request', message: 'No file provided (field name: "file").' });
    }
    let bytes: Buffer;
    try {
      bytes = await data.toBuffer();
    } catch {
      return reply.status(400).send({ error: 'bad_request', message: 'Could not read upload.' });
    }
    if (data.file.truncated) {
      return reply
        .status(413)
        .send({ error: 'too_large', message: `File exceeds the ${Math.round(config.maxUploadBytes / 1024 / 1024)} MB limit.` });
    }
    const query = req.query as { reputation?: string; detonate?: string; fresh?: string };
    const bytesU8 = new Uint8Array(bytes);
    const sha256 = hashBytes(bytesU8).sha256;
    const repOn = query.reputation ? query.reputation === 'true' : config.reputationDefault;
    const detOn = query.detonate === 'true';
    const cacheKey = `f:${sha256}:${repOn}:${detOn}`;

    if (query.fresh !== 'true') {
      const cached = scanCache.get(cacheKey);
      if (cached) return cached;
    }

    const report = await analyzeFile(
      { filename: data.filename, bytes: bytesU8, declaredType: data.mimetype },
      { reputation: repOn, detonate: detOn },
      { config, registry, rules },
    );

    // Encrypted, hash-addressed quarantine (opt-in); never re-served.
    if (quarantine) {
      try {
        quarantine.store(bytesU8, sha256);
      } catch {
        /* quarantine is best-effort; never block a scan on it */
      }
    }

    scanCache.set(cacheKey, report, config.scanCacheTtlMs);
    db.insertReport(report, hashIp(req.ip));
    return report;
  });

  // ── history / detail / stats / ioc search ──
  app.get('/api/scan/:id', async (req, reply) => {
    const { id } = req.params as { id: string };
    const report = db.getReport(id);
    if (!report) return reply.status(404).send({ error: 'not_found', message: 'No scan with that id.' });
    return report;
  });

  app.get('/api/scans', async (req) => {
    const q = req.query as Record<string, string>;
    return {
      scans: db.listScans({
        limit: q.limit ? Number(q.limit) : undefined,
        offset: q.offset ? Number(q.offset) : undefined,
        kind: q.kind === 'url' || q.kind === 'file' ? q.kind : undefined,
        verdict: q.verdict === 'safe' || q.verdict === 'suspicious' || q.verdict === 'malicious' ? q.verdict : undefined,
      }),
    };
  });

  app.get('/api/stats', async () => db.stats());

  app.get('/api/iocs/:value', async (req) => {
    const { value } = req.params as { value: string };
    return { value, scans: db.searchByIoc(value) };
  });

  app.addHook('onClose', async () => {
    if (!deps.db) db.close();
  });

  return app;
}
