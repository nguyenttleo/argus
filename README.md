# Argus

Argus is a self-hosted URL and file threat scanner. I built it around one practical question:

> Should I trust this?

Paste a suspicious URL or upload a file and Argus returns a clear verdict: `safe`, `suspicious`, or
`malicious`. The report includes the score, the evidence behind the score, extracted IOCs, and the
details that matter for follow-up.

The scanner is defensive by default. It does not execute uploaded files, and URL fetching is routed
through an SSRF guard before any network request is made.

## What It Does

- Scans URLs with lexical checks, DNS checks, TLS inspection, safe fetching, page-content signals,
  and optional reputation lookups.
- Scans files with hashing, magic-byte detection, extension mismatch checks, entropy, YARA-style
  rules, static document analysis, PE analysis, and optional hash reputation.
- Produces deterministic reports with weighted signals instead of a bare label.
- Works offline when API keys are missing, then adds reputation data when keys are available.
- Shares the same scanning engine across the web app, REST API, and CLI.

## Quick Start

Requirements:

- Node.js `>=24`
- npm

```bash
npm install
npm test

# CLI, no server needed
npm run demo
node packages/cli/src/cli.ts url https://example.com
node packages/cli/src/cli.ts file ./some-file

# Full stack
npm run seed
npm run server
npm run web:install
npm run web
```

Local services:

- API: `http://127.0.0.1:8089`
- Web app: `http://localhost:3001`

The demo command runs a benign URL, a phishing-style URL, and the EICAR test file so the report flow
can be checked without using a live sample.

## Repository Layout

| Path | Purpose |
| --- | --- |
| `packages/shared` | Shared types and the scoring engine |
| `packages/engine` | URL analysis, file analysis, YARA-style rules, static analysis, and reputation providers |
| `packages/server` | Fastify API, SQLite persistence, scan history, quarantine, and rate limiting |
| `packages/cli` | Terminal interface for URL, file, and demo scans |
| `web` | Next.js dashboard for submitting scans and reading reports |
| `scripts` | Production start, smoke test, and helper scripts |
| `docs` | Deployment notes |

## How Scanning Works

1. Input is normalized and validated.
2. URL scans run lexical checks first, then guarded DNS and fetch checks when enabled.
3. File scans hash the upload, detect type, inspect static structure, and run local rules.
4. Optional reputation providers add outside context when keys are configured.
5. Signals are weighted and combined into a final score and verdict.
6. The final report is returned through the CLI, API, or dashboard.

Reports include:

- Verdict and 0-100 score
- Confidence level
- Short summary
- Signal breakdown with severity, weight, and explanation
- Extracted IOCs
- URL-specific or file-specific detail blocks

## Security Model

| Risk | Argus behavior |
| --- | --- |
| Uploaded malware runs on the host | Files are hashed and statically inspected, never executed |
| SSRF through URL scanning | DNS is resolved first, private and reserved ranges are blocked, sockets are pinned to vetted IPs, and redirects are checked again |
| Malicious web content executes during a scan | Response bytes are read and inspected, not executed in the scanner |
| Zip bombs or parser abuse | Archives are inspected from declared metadata instead of fully decompressed |
| Quarantine leakage | Optional quarantine is AES-256-GCM encrypted, hash-addressed, short-lived, and not exposed through a download route |
| Scan abuse | Upload size limits and per-IP rate limits are enforced |
| Client privacy | Client IPs are stored as HMAC values, not raw addresses |

## URL Analysis

Argus checks for common URL risk signals, including:

- Punycode and suspicious IDN usage
- IP-literal hosts
- Credential tricks such as `@` in the authority section
- Suspicious TLDs and unusual URL length
- Redirect chains
- TLS certificate issues
- DNS, SPF, and DMARC signals
- Password forms, cross-domain forms, brand impersonation hints, and obfuscated page content
- Reputation hits from configured providers

The fetcher is designed for hostile input. It blocks private, loopback, link-local, reserved,
IPv4-mapped IPv6, and cloud metadata ranges before connecting.

## File Analysis

Argus inspects files without running them. Current checks include:

- SHA-256, SHA-1, and MD5
- Magic-byte type detection
- Extension mismatch detection
- Entropy checks
- YARA-style local rules
- EICAR detection
- Office and PDF static checks
- PE imports, sections, imphash, Authenticode metadata, and packer indicators
- Archive structure checks for extreme compression ratios
- IOC extraction for URLs, IPs, emails, CVEs, registry paths, cryptocurrency addresses, and onion addresses

## API

Start the API:

```bash
npm run server
```

Common endpoints:

```text
POST /api/scan/url
POST /api/scan/file
GET  /api/scan/:id
GET  /api/scans?limit&offset&kind&verdict
GET  /api/stats
GET  /api/iocs/:value
GET  /api/health
```

Example URL scan:

```bash
curl -s http://127.0.0.1:8089/api/scan/url \
  -H "content-type: application/json" \
  -d '{"url":"http://paypal.com@secure-paypa1-login.tk/webscr","fetch":true,"reputation":true}' \
  | jq .
```

## CLI

```text
argus url  <url>   [--no-fetch] [--no-reputation] [--json]
argus file <path>  [--no-reputation] [--detonate] [--json]
argus demo
```

Exit codes:

| Code | Meaning |
| --- | --- |
| `0` | Safe |
| `1` | Suspicious |
| `2` | Malicious |
| `3` | Error |

## Configuration

All configuration is optional. Copy `.env.example` to `.env` and fill in only the providers or
runtime settings you need.

Useful settings:

| Variable | Purpose |
| --- | --- |
| `GOOGLE_SAFE_BROWSING_API_KEY` | URL reputation |
| `VIRUSTOTAL_API_KEY` | File hash reputation |
| `URLHAUS_AUTH_KEY` | URL and malware-family reputation |
| `ABUSE_CH_AUTH_KEY` | Optional separate abuse.ch key |
| `ARGUS_DATA_DIR` | SQLite and runtime data directory |
| `ARGUS_MAX_UPLOAD_BYTES` | File upload limit |
| `ARGUS_IP_HASH_SECRET` | Secret used before storing client IP hashes |
| `ARGUS_QUARANTINE` | Enables encrypted quarantine when set to `true` |
| `ARGUS_API` | API target used by the web proxy |

With no keys, Argus still runs local heuristic, signature, and static-analysis checks.

## Deployment

Production entry points:

```bash
npm run verify
npm start
npm run smoke
```

The Docker setup runs the public Next.js app and a private Fastify API in one container. The web app
listens on `PORT`; the API stays on loopback and stores SQLite data under `/data`.

See `docs/DEPLOYMENT.md` for Docker, Render, persistent storage, environment variables, and smoke
test notes.

## Testing

```bash
npm test
npm run typecheck
npm run web:build
npm run verify
```

The test suite covers scoring, URL parsing, SSRF filtering, safe fetching, YARA-style rule parsing,
file analysis, quarantine behavior, API routes, and CLI rendering.

## Status

Implemented:

- URL scanner with heuristics, safe fetching, TLS inspection, page-content signals, and reputation hooks
- File scanner with hashing, static analysis, YARA-style rules, PE checks, and IOC extraction
- Explainable scoring model
- Web dashboard
- REST API
- CLI
- SQLite-backed scan history
- Encrypted quarantine
- Docker deployment path

Planned:

- Additional reputation providers
- More document-format checks
- Browser extension
- Stronger scan-history filtering and export tools
