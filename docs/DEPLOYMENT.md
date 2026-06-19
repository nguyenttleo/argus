# Argus Public Deployment

Argus is a two-process app at runtime:

- A private Fastify API that scans URLs/files and writes SQLite data.
- A public Next.js app that proxies `/api/*` requests to the private API.

For public hosting, the simplest reliable shape is one Docker web service that starts both
processes. The public port belongs to Next.js. The API listens on loopback inside the container.

## Production Entry Points

```bash
npm run verify
npm start
npm run smoke
```

`npm start` runs `scripts/start-public.mjs`, which starts:

- API: `127.0.0.1:${ARGUS_API_PORT:-8089}`
- Web: `0.0.0.0:${PORT:-3001}`

The web proxy reads `ARGUS_API` at runtime. In the single-container setup, keep it as:

```bash
ARGUS_API=http://127.0.0.1:8089
```

## Required Production Settings

Set these before public launch:

```bash
NODE_ENV=production
ARGUS_IP_HASH_SECRET=<random long secret>
ARGUS_DATA_DIR=/data
ARGUS_DB_PATH=/data/argus.sqlite
ARGUS_API_PORT=8089
ARGUS_API=http://127.0.0.1:8089
ARGUS_RATE_LIMIT_MAX=120
ARGUS_RATE_LIMIT_WINDOW_MS=60000
```

Optional reputation/sandbox integrations:

```bash
GOOGLE_SAFE_BROWSING_API_KEY=
VIRUSTOTAL_API_KEY=
URLHAUS_AUTH_KEY=
ABUSE_CH_AUTH_KEY=
TARTARUS_URL=
```

## Docker

Build and run locally:

```bash
docker compose up --build
```

Then verify:

```bash
ARGUS_PUBLIC_URL=http://localhost:3001 npm run smoke
```

The Docker image declares `/data` as a volume. Mount it on your host/provider so SQLite scan
history persists across restarts and deploys.

## Render

This repo includes `render.yaml` for a single Docker web service with:

- `healthCheckPath: /api/health`
- a persistent disk mounted at `/data`
- generated `ARGUS_IP_HASH_SECRET`
- production defaults for the public web service and private API

After the first deploy, run the smoke test from your machine:

```bash
ARGUS_PUBLIC_URL=https://<your-render-service>.onrender.com npm run smoke
```

## Operational Notes

- Keep one instance when using SQLite on a local persistent disk. Scaling horizontally requires a
  shared database or a per-instance data strategy.
- Do not expose the Fastify API directly unless you also configure CORS, rate limits, and network
  access intentionally. The default public surface should be the Next.js app.
- If you enable `ARGUS_QUARANTINE=true`, keep `/data` persistent and monitor disk usage.
- The default rate limit applies to scan routes only. Dashboard health/history polling is not
  counted against the scan budget.
