# Argus - URL & File Threat Scanner

> An all-seeing **“is this safe?”** scanner. Paste a suspicious **URL** to get a phishing-risk
> report, or drop a **file** to scan it for malware. Defensive by design - Argus treats every
> input as hostile, **never executes uploads on the host**, and fetches URLs only through an
> anti-SSRF sandbox.

Argus answers one question for non-experts and SOC analysts alike: *should I trust this?* It
fuses lexical heuristics, real signature/YARA detection, and reputation intelligence into a single
**Safe / Suspicious / Malicious** verdict - always with a transparent, explainable breakdown of
*why*. Two surfaces (URL analysis, file scanning) share one scoring & report engine.

Part of a four-project security suite: **Tartarus** (sandbox) · **Labyrinth** (CTF) ·
**Siren** (honeypot) · **Argus** (this - the defensive counterpart).

---

## Highlights

- 🛡️ **The hard part, solved well - safely handling hostile input.** A from-scratch
  [SSRF guard](packages/engine/src/url/ssrf.ts) resolves DNS first, blocks every private /
  loopback / link-local / reserved range (including the `169.254.169.254` cloud-metadata
  endpoint), and **pins the socket to the vetted IP** so DNS can’t be rebound between check and
  connect. Redirects are re-guarded on every hop.
- 🧬 **Real detection, no magic binaries.** A [YARA-subset engine](packages/engine/src/file/yara.ts)
  written in TypeScript parses real `.yar` rules (text/hex/regex strings, `N of them`,
  `uint16(0)==0x5A4D`, `filesize`, boolean conditions) - no native libyara. Plus magic-byte type
  detection, Office/PDF/PE static analysis, a zip-bomb guard, and EICAR detection.
- 🧮 **Explainable, deterministic scoring.** Verdicts are never bare labels - they’re the
  [noisy-OR combination](packages/shared/src/scoring.ts) of weighted `Signal`s, and the full
  breakdown travels with every verdict. Same input → same verdict, every time.
- 🔌 **Works fully offline.** Reputation providers (Safe Browsing, URLhaus, VirusTotal-by-hash)
  are pluggable and degrade gracefully to “unavailable” without API keys - the heuristic +
  signature engine stands on its own.
- 🖥️ **Three surfaces, one engine:** a polished Next.js web app, a REST API, and a CLI all share
  the exact same analysis code.

---

## Quick start

Requirements: **Node ≥ 24** (uses built-in `node:sqlite`, the native test runner, and TypeScript
type-stripping - there is no build step for the backend).

```bash
npm install            # install workspace deps
npm test               # 131 tests (node:test) - engines, scoring, server, CLI

# CLI - self-contained, no server needed
npm run demo                                   # benign URL + phishing URL + EICAR
node packages/cli/src/cli.ts url https://example.com
node packages/cli/src/cli.ts file ./some-file

# Full stack (API + web dashboard)
npm run seed           # optional: load demo scans for the dashboard
npm run server         # REST API on http://127.0.0.1:8089
npm run web:install    # one-time: install the web app's deps
npm run web            # dashboard on http://localhost:3001
```

Then open the dashboard and click a **safe demo** button (benign URL · phishing URL · EICAR test
file) for an instant, risk-free, explainable verdict.

---

## Architecture

```
              ┌──────────────────────────────────────────────┐
 user ───────▶│  Next.js web app  (URL box · dropzone · report)│
              └───────────────┬──────────────────────────────┘
                              │  same-origin /api/* proxy (no CORS)
                       ┌──────▼───────┐
                       │  REST API     │  Fastify · validate · rate-limit · persist
                       │  (@argus/server)
                       └──┬────────┬──┘
                url job   │        │  file job          ┌── CLI (@argus/cli) ──┐
          ┌───────────────▼──┐  ┌──▼───────────────┐    │ shares the same engine│
          │ URL analyzer      │  │ File analyzer     │◀──┘
          │ lexical + SSRF-   │  │ hash · magic ·    │
          │ safe fetch + TLS  │  │ YARA · static     │
          └───────┬──────────┘  └────────┬──────────┘
                  │ reputation            │ hash reputation / (opt) detonate
          ┌───────▼──────────┐    ┌───────▼─────────┐
          │ Safe Browsing /   │    │ VirusTotal /     │
          │ URLhaus / local   │    │ Tartarus (v3)    │
          └──────────────────┘    └─────────────────┘
                       ┌────────────────────────────┐
                       │ scoring engine (@argus/shared) │──▶ SQLite (scans, IOCs)
                       └────────────────────────────┘     + encrypted quarantine
```

**Monorepo** (npm workspaces, TypeScript, ESM, no build step):

| Package | Role |
| --- | --- |
| [`@argus/shared`](packages/shared) | Types + the deterministic noisy-OR scoring engine |
| [`@argus/engine`](packages/engine) | URL & file analysis: SSRF guard, fetcher, lexical heuristics, YARA-subset, static analysis, reputation providers |
| [`@argus/server`](packages/server) | Fastify REST API · SQLite persistence · encrypted quarantine · rate limiting |
| [`@argus/cli`](packages/cli) | `argus url` / `argus file` with an explainable terminal report |
| [`web`](web) | Standalone Next.js 16 dashboard (App Router, React 19, Tailwind v4) |

> **Why TypeScript/Node, not the Go stack the spec sketches?** Go/Docker/ClamAV/YARA aren’t
> installed on the target machine; Node is the only runnable backend (the sibling projects made the
> same call). The consequence is a feature, not a compromise: the detection engines are **real,
> readable TypeScript** rather than shell-outs to absent binaries.

---

## Security model (the heart of the project)

| Threat | Mitigation |
| --- | --- |
| **Executing malware on the host** | Files are **never executed** - only hashed, magic/YARA/static-scanned. Behavioural detonation happens only inside **Tartarus**, opt-in. |
| **SSRF via the URL fetcher** | DNS resolved first; **all** private/reserved/loopback/link-local ranges blocked (incl. `169.254.169.254`, IPv4-mapped IPv6, NAT64); socket **pinned** to the vetted IP (anti-rebinding); every redirect re-guarded; http/https only; hard byte/redirect/wall-clock caps. |
| **Fetching a live malicious page** | Bytes are *read*, never run; invalid TLS is inspected & reported, never trusted. |
| **Quarantine / leakage** | Uploads (opt-in) stored **AES-256-GCM encrypted**, hash-addressed, short-TTL, swept - and **never re-served** (no download route). Default is hash-only retention. |
| **Zip bombs / parser DoS** | Argus never decompresses archives; it reads the ZIP central directory and flags extreme ratios / nesting from declared sizes. |
| **Abuse relay / scan-by-proxy** | Per-IP rate limiting; http/https allowlist; upload size gate. |
| **Privacy** | Only an **HMAC of the client IP** is stored, never the raw IP. |

---

## Capability vs the market

The bar for "is this URL/file safe?": **VirusTotal** (file/URL multi-engine + static analysis),
**urlscan.io** (deep URL/page analysis), **Google Safe Browsing** (URL reputation). Argus is at
parity on the analysis it performs and ahead on explainability, privacy and self-hostability.

**URL analysis**

| | Argus | VirusTotal | urlscan.io | Safe Browsing |
| --- | :-: | :-: | :-: | :-: |
| Lexical/structural heuristics (typosquat, punycode, IDN, `@`-trick, …) | ✅ 19 checks | ◐ | ◐ | ✕ |
| Reputation feeds (Safe Browsing · URLhaus · pluggable) | ✅ | ✅ | ◐ | ✅ |
| SSRF-safe fetch + re-guarded redirect chain | ✅ socket-pinned | ✅ | ✅ | ✕ |
| TLS certificate inspection | ✅ | ◐ | ✅ | ✕ |
| **Domain age (RDAP/WHOIS)** | ✅ | ✅ | ✅ | ✕ |
| **DNS · SPF · DMARC** | ✅ | ◐ | ✅ | ✕ |
| **Page content: password/cross-domain forms, brand impersonation, obfuscation** | ✅ | ◐ | ✅ | ✕ |
| Headless screenshot | ✕ by design¹ | ✕ | ✅ | ✕ |
| **Explainable verdict + full signal breakdown** | ✅ unique | ◐ engine list | ◐ | ✕ binary |

**File analysis**

| | Argus | VirusTotal |
| --- | :-: | :-: |
| sha256/sha1/md5 · entropy · magic-byte type + extension-mismatch | ✅ | ✅ |
| YARA | ✅ from-scratch engine | ✅ |
| **PE: imphash · imports · per-section entropy · Authenticode · packer** | ✅ | ✅ |
| Office/OLE macro · PDF active-content · zip-bomb guard | ✅ | ◐ |
| Multi-AV reputation | ✅ via VT-by-hash | ✅ 70+ native |
| **Malware-family attribution** | ✅ MalwareBazaar | ✅ |
| Behavioural detonation | ◐ Tartarus (opt-in) | ✅ sandbox |
| IOC extraction (url/ip/email/**btc/eth/cve/registry/onion**) | ✅ | ✅ |

**Where Argus is ahead:** a deterministic, weighted **signal breakdown** behind every verdict
(competitors give an engine count or a binary flag); **works fully offline / self-hosted** with zero
API keys; **privacy** (client IP is HMAC-hashed, no raw-input hoarding); SSRF-safe-by-design fetch;
one engine driving a **CLI + REST API + web** surface; result caching + concurrent lookups.

**Where it integrates rather than re-implements:** the 70+ native AV engines (reached via VT-by-hash),
turnkey behavioural sandboxing (delegated to **Tartarus**), and page screenshots (¹deliberately
omitted - safely rendering attacker JS requires an isolated browser, which is Tartarus's job, not a
gap in the static analysis Argus does perform).

Net: for the single-input "should I trust this?" question, Argus matches its best competitor on
analysis depth and exceeds it on explainability, privacy and deployability.

---

## API

`POST /api/scan/url` - `{ "url": "...", "fetch": true, "reputation": true }` → `Report`
`POST /api/scan/file` - `multipart/form-data` field `file` → `Report`
`GET  /api/scan/:id` · `GET /api/scans?limit&offset&kind&verdict` · `GET /api/stats`
`GET  /api/iocs/:value` (find scans by IOC) · `GET /api/health`

```bash
curl -s localhost:8089/api/scan/url -H 'content-type: application/json' \
  -d '{"url":"http://paypal.com@secure-paypa1-login.tk/webscr"}' | jq .verdict
# → "malicious"
```

A `Report` carries the `verdict`, 0–100 `score`, `confidence`, a one-line `summary`, the full
`signals[]` breakdown (each with severity, weight and a plain-English explanation), extracted
`iocs[]`, and a kind-specific `detail` block.

---

## CLI

```
argus url  <url>   [--no-fetch] [--no-reputation] [--json]
argus file <path>  [--no-reputation] [--detonate]    [--json]
argus demo

Exit codes: 0 safe · 1 suspicious · 2 malicious · 3 error   (pipeline-friendly)
```

---

## Configuration

Everything is optional - see [`.env.example`](.env.example). With **no** keys, Argus runs fully
offline; add `GOOGLE_SAFE_BROWSING_API_KEY`, `VIRUSTOTAL_API_KEY`, `URLHAUS_AUTH_KEY` to light up
live reputation, and `TARTARUS_URL` for sandboxed detonation.

## Public hosting

Argus now ships with a production entrypoint and Docker deployment files:

```bash
npm run verify
npm start
npm run smoke
```

For public hosting, use the single-container Docker setup in [`Dockerfile`](Dockerfile): the Next.js
web app listens on the public `PORT`, while the Fastify API stays private on loopback and stores
SQLite data under `/data`. See [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md) for Render, Docker, env
vars, persistent storage, and smoke-test instructions.

---

## Testing

```bash
npm test          # 131 tests across engines, scoring, server (Fastify inject), CLI
npm run typecheck # strict tsc --noEmit across all packages
npm run web:build # production Next.js build
```

The SSRF guard, IP classifier, YARA engine and scoring model are exhaustively unit-tested;
the server is tested via `fastify.inject()`; the URL fetcher’s read path is tested against a local
server and verified live against real sites.

> **A note on test fixtures.** Malicious samples (EICAR, webshells) are assembled at runtime from
> base64 / string-concatenation so no source file contains a contiguous live signature - otherwise
> endpoint AV (Windows Defender) quarantines the repo’s own files. This is the same reason real
> AV/YARA projects ship encoded samples.

---

## Roadmap status

- **M1 (MVP)** ✅ URL heuristics + reputation, file upload + SHA-256 + hash reputation + ClamAV-class
  signature/YARA scan + explainable report (web + API + CLI).
- **M2** ✅ (mostly) SSRF-safe redirect-chain resolution + TLS inspection; YARA + macro/PE/PDF static
  analysis; history + IOC search.
- **M3** ◐ Tartarus detonation hook + REST API/CLI shipped; ML scoring & browser extension are future work.

---

*Argus is a portfolio project - a defensive counterpart to offensive/AppSec work that visibly
solves the genuinely hard part: safely handling hostile input.*
