# Argus - Build Progress

> Living log of what's built, why key decisions were made, and what's verified.
> Newest entries at the top of each section.

## Status snapshot

| Component | State | Verified |
| --- | --- | --- |
| Monorepo scaffold (`@argus/shared|engine|server|cli` + `web`) | ✅ done | npm install, native-TS run, cross-pkg import |
| `@argus/shared` - types + scoring engine | ✅ done | 10 unit tests pass, typecheck clean |
| `@argus/engine` - URL analysis | ✅ done | 55 unit tests + live E2E (real fetch, live SSRF block) |
| `@argus/engine` - file analysis | ✅ done | 25 unit tests + in-memory E2E (EICAR/PE/webshell/benign) |
| `@argus/server` - Fastify REST API | ✅ done | 14 integration tests + live curl (URL/file/stats/IOC/ratelimit) |
| `@argus/cli` | ✅ done | 5 render tests + live run (demo/url/file, exit codes, --json) |
| `web` - Next.js app | ✅ done | live browser E2E (URL/file/EICAR, tabs, history modal, mobile) |
| E2E + review pass + docs | ✅ done | 114 tests, full typecheck, prod build, live integration sweep |

**Build complete.** 114 tests pass · `tsc --noEmit` clean across all packages · `next build`
clean · CLI, API and web verified live end-to-end.

## Architecture decisions (and why)

- **Stack: TypeScript / Node 24 monorepo + Next.js**, *not* the Go stack the spec
  sketches. Go/Docker/ClamAV/YARA are not installed on this machine; Node is the only
  runnable backend. The sibling projects (Siren, Aegis) made the same call for the same
  reason. Consequence: detection engines (SSRF guard, YARA-subset matcher, static file
  analysis, scoring) are **real TypeScript implementations**, not shell-outs to absent
  binaries. External reputation APIs (Safe Browsing, URLhaus, VirusTotal) are **pluggable
  providers** that degrade gracefully to "unavailable" without keys - the offline heuristic
  engine stands on its own.
- **No build step.** Node 24 strips TypeScript types natively (`node file.ts`), so there's
  no `tsc` emit / `tsx` / bundler in the backend loop. `tsconfig` uses `erasableSyntaxOnly`
  to guarantee every file stays strip-compatible (no enums/namespaces/param-properties).
  Verified: cross-package `@argus/shared` imports resolve through the npm-workspace symlink
  and get type-stripped correctly at runtime *and* typecheck under `tsc --noEmit`.
- **Persistence: `node:sqlite`** (built into Node 24) - real relational SQL matching the
  spec's schema, zero native deps, no DB server.
- **Tests: `node:test`** (built in) - zero test-runner dependency. `npm test` auto-discovers
  `*.test.ts`.

## Scoring model (the shared heart)

`packages/shared/src/scoring.ts`. Verdicts are **never** bare labels - they are the
deterministic output of a list of `Signal`s, and the breakdown travels with the verdict.

- **noisy-OR** combination: `riskP = 1 − Π(1 − wᵢ·cᵢ)`. Order-independent, bounded, with
  diminishing returns - ten weak signals can't out-shout one strong one, and more evidence
  never lowers risk.
- **Decisive override**: a `critical` signal at ≥0.85 confidence (e.g. EICAR, a Safe-Browsing
  hit) forces `malicious` and bypasses mitigation - a real signature beats a good reputation.
- **Mitigation**: benign evidence (old domain, valid CA cert, popular host) dampens
  *non-decisive* scores to cut false positives.
- Thresholds: `<25 safe · 25–59 suspicious · ≥60 malicious`.
- Verdict **confidence** is separate from per-signal confidence: lower near a threshold or on
  thin evidence, higher when corroborated or far from a boundary.

## URL analysis engine (`packages/engine/src/url/`, `reputation/`)

- **`ip.ts`** - pure IPv4/IPv6 parser + special-range classifier (loopback, RFC-1918,
  link-local incl. `169.254.169.254`, CGNAT, multicast, IPv4-mapped/NAT64 unwrapping…).
  Caught a real bypass in review: IPv4-mapped IPv6 (`::ffff:169.254.169.254`) was slipping
  through until a prefix-comparison bug was fixed. 10 tests.
- **`ssrf.ts`** - DNS-resolving guard: refuses if *any* resolved address is non-public,
  returns the vetted IP to **pin** the socket to (anti-rebinding). Loopback/internal names
  refused pre-DNS. 9 tests.
- **`fetcher.ts`** - SSRF-safe fetcher: manual redirects re-guarded each hop, socket pinned
  to the vetted IP via custom `lookup`, hard caps on redirects/bytes/time, TLS cert
  inspection, `rejectUnauthorized:false` (inspect hostile certs, never trust). 7 tests.
- **`lexical.ts` + `data.ts`** - offline heuristics: `@`-credential trick, raw-IP host,
  punycode/homograph (mixed-script), brand typosquat (de-confused Levenshtein), brand-in-
  subdomain, abused TLDs, deep subdomains, shorteners, phishing keywords, hyphen-stuffing,
  odd ports, executable links, open-redirect params, length; popular-domain allowlist as a
  *mitigating* signal. 15 tests.
- **`reputation/`** - pluggable providers (URLhaus, Safe Browsing, VirusTotal-by-hash) +
  always-on bundled local feed; TTL cache; concurrent + timeout-bounded; providers NEVER
  throw (degrade to "unavailable"). 5 tests.
- **`analyze.ts`** - orchestrator fusing all of the above → scored `Report`. 9 tests.
- **Live-verified:** real HTTPS fetch of example.com (captured Cloudflare cert, 72d to
  expiry); crafted phishing URL → malicious with explained signals; **SSRF guard refused
  `169.254.169.254` and `localhost` live**.

## File analysis engine (`packages/engine/src/file/`)

- **`hash.ts`** - sha256/sha1/md5 + Shannon entropy (packing/encryption tell).
- **`magic.ts`** - magic-byte type detection (PE/ELF/Mach-O/OLE/PDF/ZIP/images/…) +
  extension-mismatch logic; flags "executable masquerading as a .pdf/.jpg".
- **`yara.ts`** - **from-scratch YARA-subset engine** (no libyara). Parses real `.yar`
  files: text/hex(`??`+jumps)/regex strings with nocase/wide/fullword; conditions with
  `N of them`, `$a at`, `#a`, `uint16/32`, `filesize`, boolean logic, parentheses.
  Two real bugs caught in review: (1) brace-matcher counted the `}` inside the EICAR
  string; (2) the comment-stripper mangled `https://` URLs inside meta strings. Both
  fixed; a malformed rule is now skipped, never fatal. 14 tests.
- **`rules/builtin.yar`** - 8 real rules (EICAR, PE-injection-imports, Office VBA, PDF
  active content, PHP webshell, PowerShell download-exec, WSH dropper).
- **`static.ts`** - ZIP central-directory parse → OOXML macro + **zip-bomb ratio guard**;
  OLE macro markers; PDF active-content; PE header parse (machine/subsystem/DLL/packer);
  script-obfuscation heuristics; IOC extraction (URL/IP/email).
- **`detonate.ts`** - optional Tartarus detonation (v3): ships py/js payloads to the
  sandbox only when opted in + `TARTARUS_URL` set; degrades to "unavailable" otherwise.
- **`analyze.ts`** - orchestrator → scored `Report`. **Files are never executed.** 10 tests.
- **Live-verified (in-memory):** EICAR → malicious 97 w/ correct sha256; MZ-bytes named
  `invoice.pdf` → masquerade + PE-imports; PHP webshell → malicious 92; benign → safe.
  (On-disk EICAR is quarantined by the host's real Defender - itself proof EICAR is live.)

## API server (`packages/server/src/`)

- **`app.ts`** - Fastify app (`buildApp(config, deps)` for injectable testing). Routes:
  `POST /api/scan/url`, `POST /api/scan/file` (multipart, size-gated), `GET /api/scan/:id`,
  `GET /api/scans` (filterable history), `GET /api/stats`, `GET /api/iocs/:value`,
  `GET /api/health`. CORS + per-IP rate limiting (`x-ratelimit-*` headers). Only an HMAC
  of the client IP is stored, never the raw IP.
- **`db.ts`** - `node:sqlite` persistence matching the spec model (scans / url_scans /
  file_scans / iocs) + full report JSON for detail; IOC search across scans.
- **`quarantine.ts`** - AES-256-GCM, hash-addressed, TTL-swept; **no HTTP retrieval
  route** (never re-served). Opt-in (`ARGUS_QUARANTINE=1`); default is hash-only retention.
- **`seed.ts`** - `npm run seed` loads demo scans (offline) for the dashboard.
- **Live-verified:** started on :8099, scanned benign+phishing URLs, uploaded a
  masquerading PE (→ malicious) and a benign note (→ safe), confirmed `/api/stats`,
  `/api/scans`, IOC search and rate-limit headers over real HTTP.

## Web app (`web/`)

Standalone Next.js 16 (App Router, Turbopack, React 19, Tailwind v4). The browser calls
same-origin `/api/*` **proxy routes** that forward to the Argus API server-side - no CORS,
backend URL hidden. The web app keeps its own copy of the API types (the boundary is JSON).

- **`components/Scanner.tsx`** - URL box + file dropzone (client-side size gate) + safe-demo
  buttons (benign/phishing/EICAR, EICAR built from base64 so the bundle has no live signature).
- **`components/ReportCard.tsx`** - the explainable verdict: colored badge, SVG risk gauge,
  plain-English summary, per-signal breakdown (severity dot + weight + explanation),
  "Why this verdict" vs "Technical details" tabs, IOC chips.
- **`components/Sidebar.tsx`** - live stats + recent-scan history; click a row → modal report.
- **Live browser-verified:** phishing URL → MALICIOUS 92 with full signal
  breakdown incl. live SSRF-guard NXDOMAIN handling; EICAR file → MALICIOUS 97 with correct
  sha256 + YARA badge; Technical-details tab; history modal; mobile (375px) layout; 0 console
  errors.

### UI revamp - "observation deck" identity

The first UI was functional but generic. Rebuilt with a distinctive identity tied to the Argus
myth (the hundred-eyed watcher whose eyes became the peacock's iridescent tail):
- **Type:** Space Grotesk (display) + JetBrains Mono (data/labels) via `next/font`; Inter body.
- **Palette:** cold void + an iridescent cyan→blue→violet brand ("the iris"); bold functional
  verdict colours (mint / amber / crimson). Tokens live in a Tailwind v4 `@theme` block.
- **Motifs:** a custom **Argus eye** mark (`EyeMark.tsx`, breathes idle / sweeps while scanning),
  reticle corner-brackets on panels, a terminal-prompt scanner (`❯`), a watchful **iris risk-gauge**
  on the report card, severity-spined signal rows, a console status bar (live clock + "systems
  nominal"), telemetry tiles + a verdict-distribution bar, scan/grain texture.
- **Bug fixed during verification:** `EyeMark`'s `Math.cos/sin` SVG coords differed by 1 ULP across
  the server/browser JS engines → an SSR **hydration mismatch**; rounding the coords to 2 dp fixed
  it (0 console errors confirmed on a clean reload). Re-verified desktop + mobile; `next build` clean.

## Defender note (real-world insight)

The host's Windows Defender quarantines any source file that contains a *contiguous live
signature* (it ate `seed.ts` and `yara.test.ts` mid-build for embedding a PHP webshell / EICAR
string). Fix applied throughout: malicious test fixtures are assembled at runtime from base64
or string-concatenation, so no repo file trips endpoint AV. The bundled `.yar` rules express
EICAR in escaped YARA syntax (not the raw bytes), so they're safe too.

## Dedicated review pass - findings & fixes

A final read-through of the security-critical and high-complexity paths surfaced (and fixed)
four real issues:

1. **Fetcher slow-drip / double-settle** - `req.setTimeout` is only an *idle* timeout, so a
   server dribbling bytes under the cap could hold a socket open indefinitely. Added an absolute
   wall-clock deadline + a single-settle guard (`packages/engine/src/url/fetcher.ts`).
2. **Oversize upload status** - `@fastify/multipart` was throwing on the size limit, surfacing as
   a generic 400. Switched to `throwFileSizeLimit:false` so oversize cleanly returns **413**.
3. **YARA per-rule re-encoding** - `scanBytes` converted the whole file to a latin1 string *once
   per rule* (O(rules×size)). Now converted once and shared (`packages/engine/src/file/yara.ts`).
4. **Missing dangerous-scheme detection** - `javascript:` / `data:` / `vbscript:` URLs (script
   injection / payload-smuggling vectors) weren't flagged. Added `url.dangerous_scheme`.

Earlier in-flight bugs caught by tests and fixed: an IPv4-mapped-IPv6 SSRF bypass
(`::ffff:169.254.169.254`), a YARA brace-matcher tripping on the `}` inside the EICAR string, and
a comment-stripper mangling `https://` URLs in rule metadata.

## Final verification

- `npm test` → **114 pass / 0 fail** (~0.8s) · `npm run typecheck` → clean · `npm run web:build` → clean.
- **Live**: CLI (`demo`, url/file, exit codes, `--json`); API over HTTP (URL/file scan, EICAR via
  stdin → malicious 97 w/ correct sha256, dangerous-scheme → suspicious, oversize → 413, stats,
  history, IOC search, rate-limit headers); web dashboard in a real browser (phishing URL →
  MALICIOUS 92 w/ full breakdown, EICAR file → MALICIOUS 97, technical-details tab, history modal,
  mobile layout, 0 console errors); SSRF guard refusing `169.254.169.254` & `localhost` live.

## Capability push - parity with VirusTotal / urlscan.io

Closed the real analysis gaps to the market leaders (see the capability matrix in the README).
Tests grew **114 → 131**; typecheck + web prod-build stay clean.

- **URL: domain age (RDAP)** - `url/rdap.ts`. Free, key-less via the rdap.org bootstrap; the single
  strongest phishing signal (young domains). Live-verified: example.com → `ageDays 11267`
  (registered 1995-08-14).
- **URL: DNS / SPF / DMARC** - `url/dns.ts`. Missing email-auth on a brand-imitating domain.
- **URL: page content analysis** - `url/content.ts`. On bytes already fetched (never executed):
  password fields, **cross-domain credential forms (critical)**, brand-on-login-page impersonation,
  meta-refresh, hidden iframes, obfuscated JS. Tightened in review: brand-impersonation now requires
  a password field, so a page merely *mentioning* a brand (e.g. github.com) is not a false positive.
- **File: deep PE** - `file/pe.ts`. Real import-table parse → **imphash** (matches pefile's algorithm,
  test-verified), suspicious-import surface, per-section entropy, Authenticode-signature presence,
  packer/driver detection.
- **File: MalwareBazaar** - `reputation/malwarebazaar.ts`. Free abuse.ch hash lookup adding malware
  **family attribution**; treated as decisive alongside VirusTotal.
- **Richer IOCs** - crypto addresses (BTC/ETH), CVEs, registry persistence keys, `.onion`, imphash.
- **Efficiency** - URL fetch + DNS + RDAP now run **concurrently** (gated on the deep-fetch toggle so
  quick scans stay fast); a TTL **full-scan cache** in the server returns identical requests instantly
  (`fresh:true` bypasses). Verified: repeat scan returns the cached report, `fresh` re-analyzes.

Assessment: at parity with its best competitor on analysis depth for the "is this safe?" use case,
and ahead on explainability, privacy, offline/self-hostability, and SSRF-safe engineering. Gaps
(70+ native AV engines, turnkey behavioural sandbox, page screenshots) are reached via integration
(VT-by-hash, Tartarus) or are deliberate safety/scope choices.

## How to run

```bash
npm install && npm test            # 131 tests
npm run demo                       # CLI safe demo
npm run seed && npm run server     # REST API :8089
npm run web:install && npm run web # dashboard :3001
```
