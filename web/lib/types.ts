


export type Verdict = 'safe' | 'suspicious' | 'malicious';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type ScanKind = 'url' | 'file';

export interface Signal {
  id: string;
  category: string;
  title: string;
  detail: string;
  severity: Severity;
  weight: number;
  confidence: number;
  mitigates?: boolean;
  evidence?: Record<string, unknown>;
}

export interface Ioc {
  type: string;
  value: string;
  note?: string;
}

export interface TlsInfo {
  valid: boolean;
  issuer?: string;
  subject?: string;
  validTo?: string;
  daysToExpiry?: number;
  selfSigned?: boolean;
  error?: string;
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
  title?: string;
}

export interface UrlScanDetail {
  kind: 'url';
  input: string;
  normalized: string;
  scheme: string;
  host: string;
  registrableDomain?: string;
  subdomain?: string;
  isIpHost: boolean;
  resolvedIps: string[];
  finalUrl?: string;
  redirects: { url: string; status: number; location: string }[];
  fetched: boolean;
  fetchError?: string;
  http?: { status?: number; server?: string; contentType?: string; bytes?: number; title?: string };
  tls?: TlsInfo;
  dns?: DnsInfo;
  rdap?: RdapInfo;
  content?: ContentInfo;
  reputation: { provider: string; available: boolean; listed: boolean; detail?: string; source?: string }[];
}

export interface PeDetail {
  machine: string;
  subsystem: string;
  isDll: boolean;
  isDriver: boolean;
  sections: { name: string; size: number; entropy: number }[];
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
  declaredType?: string;
  realType?: string;
  realTypeLabel?: string;
  typeMismatch: boolean;
  entropy: number;
  pe?: PeDetail;
  staticFindings: { id: string; title: string; detail: string; severity: Severity }[];
  yaraHits: { rule: string; tags: string[]; meta: Record<string, string>; strings: string[] }[];
  vt?: { provider: string; available: boolean; listed: boolean; detail?: string };
  mbazaar?: { provider: string; available: boolean; listed: boolean; detail?: string };
  detonation?: { available: boolean; ran: boolean; detail?: string };
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

export interface Health {
  status: string;
  service: string;
  engineVersion: string;
  rulesLoaded: number;
  reputationProviders: string[];
  quarantine: string;
}
