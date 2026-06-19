/**
 * Argus shared types - one vocabulary flowing engine → server → cli → web.
 *
 * Design rule (see README §"Why it lands"): a verdict is NEVER a bare label.
 * Every verdict is the deterministic output of a list of {@link Signal}s, and the
 * full breakdown travels with the verdict so the UI can always explain *why*.
 */

export const ENGINE_VERSION = '1.0.0';

export type ScanKind = 'url' | 'file';

/** The three-state verdict every scan resolves to. */
export type Verdict = 'safe' | 'suspicious' | 'malicious';

/** Ordered low→high; used for sorting and badge colour. */
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/** Where a signal came from - drives grouping in the report card. */
export type SignalCategory =
  | 'lexical' // URL string/structure heuristics
  | 'reputation' // 3rd-party threat feeds (Safe Browsing, URLhaus, VT…)
  | 'network' // DNS / IP / SSRF observations
  | 'tls' // certificate inspection
  | 'content' // fetched page content
  | 'static' // file static analysis (magic bytes, macros, headers)
  | 'signature' // exact known-bad signatures (e.g. EICAR)
  | 'yara' // YARA rule matches
  | 'detonation' // behavioural IOCs from sandboxed run
  | 'meta'; // scan-process notes (coverage, errors)

/**
 * A single piece of evidence contributing to (or mitigating) the risk score.
 * Weights/confidence feed the deterministic scoring model in `scoring.ts`.
 */
export interface Signal {
  /** Stable identifier, e.g. `url.ip_host`, `file.eicar`. */
  id: string;
  category: SignalCategory;
  /** Short human title shown as the row heading. */
  title: string;
  /** One- or two-sentence explanation of what fired and why it matters. */
  detail: string;
  severity: Severity;
  /** 0–100 risk contribution. For mitigating signals, the strength of mitigation. */
  weight: number;
  /** 0–1 - how sure we are this observation is real/correct. */
  confidence: number;
  /** When true, this signal REDUCES risk instead of adding it. */
  mitigates?: boolean;
  /** Structured backing data (matched string, resolved IP, cert fields…). */
  evidence?: Record<string, unknown>;
}

export type IocType =
  | 'sha256'
  | 'sha1'
  | 'md5'
  | 'domain'
  | 'ip'
  | 'url'
  | 'email'
  | 'onion'
  | 'btc'
  | 'eth'
  | 'cve'
  | 'registry';

export interface Ioc {
  type: IocType;
  value: string;
  note?: string;
}

/** The unified scan result. Same shape for URL and file scans. */
export interface Report {
  id: string;
  kind: ScanKind;
  /** Display target: the URL, or the filename (+ short sha) for files. */
  target: string;
  verdict: Verdict;
  /** 0–100. */
  score: number;
  /** 0–1 - confidence in the verdict itself, given evidence coverage. */
  confidence: number;
  /** One-line plain-English summary for non-experts. */
  summary: string;
  signals: Signal[];
  iocs: Ioc[];
  /** Kind-specific detail block. */
  detail: UrlScanDetail | FileScanDetail;
  createdAt: string; // ISO-8601
  engineVersion: string;
  durationMs: number;
}

// ── URL scan detail ──────────────────────────────────────────────────────────

export interface RedirectHop {
  url: string;
  status: number;
  location: string;
  ip?: string;
}

export interface TlsInfo {
  valid: boolean;
  issuer?: string;
  subject?: string;
  validFrom?: string;
  validTo?: string;
  daysToExpiry?: number;
  san?: string[];
  protocol?: string;
  selfSigned?: boolean;
  error?: string;
}

export interface ReputationResult {
  provider: string;
  /** Was the provider actually consulted (API key present / cache hit)? */
  available: boolean;
  /** Did the provider flag this target? */
  listed: boolean;
  categories?: string[];
  detail?: string;
  /** Where the answer came from. */
  source?: 'live' | 'cache' | 'local-feed' | 'unavailable';
}

export interface HttpInfo {
  status?: number;
  server?: string;
  contentType?: string;
  bytes?: number;
  title?: string;
}

export interface DnsInfo {
  mx: string[];
  ns: string[];
  txt: string[];
  hasSpf: boolean;
  hasDmarc: boolean;
  dmarcPolicy?: string;
  errors: string[];
}

export interface RdapInfo {
  available: boolean;
  registeredAt?: string;
  ageDays?: number;
  registrar?: string;
  statuses?: string[];
  detail?: string;
  source?: 'live' | 'cache' | 'unavailable';
}

export interface ContentInfo {
  hasPasswordField: boolean;
  formActions: string[];
  crossDomainForm?: string;
  brandsInContent: string[];
  metaRefresh?: string;
  hiddenIframes: number;
  externalScripts: number;
  obfuscation: string[];
  faviconHref?: string;
  title?: string;
}

export interface UrlScanDetail {
  kind: 'url';
  input: string;
  normalized: string;
  scheme: string;
  host: string;
  port?: number;
  path: string;
  registrableDomain?: string;
  publicSuffix?: string;
  subdomain?: string;
  isIpHost: boolean;
  resolvedIps: string[];
  finalUrl?: string;
  redirects: RedirectHop[];
  fetched: boolean;
  fetchError?: string;
  http?: HttpInfo;
  tls?: TlsInfo;
  dns?: DnsInfo;
  rdap?: RdapInfo;
  content?: ContentInfo;
  reputation: ReputationResult[];
}

// ── File scan detail ─────────────────────────────────────────────────────────

export interface StaticFinding {
  id: string;
  title: string;
  detail: string;
  severity: Severity;
}

export interface YaraHit {
  rule: string;
  namespace?: string;
  tags: string[];
  meta: Record<string, string>;
  /** Identifiers of the strings that matched, e.g. `$eicar`, `$mz`. */
  strings: string[];
}

export interface DetonationResult {
  available: boolean;
  ran: boolean;
  detail?: string;
  iocs?: Ioc[];
  source?: 'tartarus' | 'unavailable';
}

export interface PeSection {
  name: string;
  size: number;
  entropy: number;
}

export interface PeDetail {
  machine: string;
  subsystem: string;
  isDll: boolean;
  isDriver: boolean;
  sections: PeSection[];
  /** import hash (md5 of ordered dll.func list) - clusters malware families */
  imphash?: string;
  importedDlls: string[];
  suspiciousImports: string[];
  signed: boolean;
  hasResources: boolean;
  hasTls: boolean;
  packerHint?: string;
  compiledAt?: string;
}

export interface FileScanDetail {
  kind: 'file';
  filename: string;
  size: number;
  sha256: string;
  sha1?: string;
  md5?: string;
  /** ssdeep-style fuzzy hash for similarity clustering. */
  fuzzy?: string;
  /** From the supplied extension / client-declared MIME. */
  declaredType?: string;
  /** Inferred from magic bytes. */
  realType?: string;
  realTypeLabel?: string;
  typeMismatch: boolean;
  /** Shannon entropy of the bytes (0–8). High ⇒ packed/encrypted. */
  entropy: number;
  pe?: PeDetail;
  staticFindings: StaticFinding[];
  yaraHits: YaraHit[];
  vt?: ReputationResult;
  mbazaar?: ReputationResult;
  detonation?: DetonationResult;
}

// ── History / stats projections ──────────────────────────────────────────────

/** Lightweight row for history lists (no heavy detail/signals). */
export interface ScanSummary {
  id: string;
  kind: ScanKind;
  target: string;
  verdict: Verdict;
  score: number;
  confidence: number;
  summary: string;
  createdAt: string;
  engineVersion: string;
}

export interface Stats {
  total: number;
  byVerdict: Record<Verdict, number>;
  byKind: Record<ScanKind, number>;
}

// ── Scan request shapes (API/CLI) ────────────────────────────────────────────

export interface UrlScanOptions {
  /** Resolve redirect chain + fetch content through the SSRF-safe fetcher. */
  fetch?: boolean;
  /** Consult external reputation providers (requires keys). */
  reputation?: boolean;
}

export interface FileScanOptions {
  /** Consult VirusTotal by hash (requires key). */
  reputation?: boolean;
  /** Detonate in Tartarus if static analysis is inconclusive-but-suspicious. */
  detonate?: boolean;
}
