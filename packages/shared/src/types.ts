

export const ENGINE_VERSION = '1.0.0';

export type ScanKind = 'url' | 'file';


export type Verdict = 'safe' | 'suspicious' | 'malicious';


export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';

export const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};


export type SignalCategory =
  | 'lexical'
  | 'reputation'
  | 'network'
  | 'tls'
  | 'content'
  | 'static'
  | 'signature'
  | 'yara'
  | 'detonation'
  | 'meta';


export interface Signal {

  id: string;
  category: SignalCategory;

  title: string;

  detail: string;
  severity: Severity;

  weight: number;

  confidence: number;

  mitigates?: boolean;

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


export interface Report {
  id: string;
  kind: ScanKind;

  target: string;
  verdict: Verdict;

  score: number;

  confidence: number;

  summary: string;
  signals: Signal[];
  iocs: Ioc[];

  detail: UrlScanDetail | FileScanDetail;
  createdAt: string;
  engineVersion: string;
  durationMs: number;
}



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

  available: boolean;

  listed: boolean;
  categories?: string[];
  detail?: string;

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

  fuzzy?: string;

  declaredType?: string;

  realType?: string;
  realTypeLabel?: string;
  typeMismatch: boolean;

  entropy: number;
  pe?: PeDetail;
  staticFindings: StaticFinding[];
  yaraHits: YaraHit[];
  vt?: ReputationResult;
  mbazaar?: ReputationResult;
  detonation?: DetonationResult;
}




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



export interface UrlScanOptions {

  fetch?: boolean;

  reputation?: boolean;
}

export interface FileScanOptions {

  reputation?: boolean;

  detonate?: boolean;
}
