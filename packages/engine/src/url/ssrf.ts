/**
 * SSRF guard - the safety heart of URL analysis.
 *
 * Before Argus ever opens a socket to a submitted URL it must prove the
 * destination is a publicly-routable host. The guard:
 *   1. rejects non-http(s) schemes outright;
 *   2. resolves the hostname to *every* A/AAAA address;
 *   3. refuses if ANY resolved address is private/loopback/link-local/reserved
 *      (so a name that resolves to both a public and an internal IP is still
 *      blocked - defeats "0.0.0.0" / split-horizon / partial-rebinding tricks);
 *   4. returns the vetted IP to **pin** the connection to, so the socket can't be
 *      re-pointed at an internal address between resolution and connect (TOCTOU /
 *      DNS-rebinding).
 *
 * The DNS resolver is injectable so the decision logic is unit-testable offline.
 */

import dnsPromises from 'node:dns/promises';
import { classifyIp, isIpLiteral } from './ip.ts';

export interface ResolvedAddr {
  address: string;
  family: number;
}

export type Resolver = (host: string) => Promise<ResolvedAddr[]>;

export const ALLOWED_PROTOCOLS = new Set(['http:', 'https:']);

export function isAllowedProtocol(protocol: string): boolean {
  return ALLOWED_PROTOCOLS.has(protocol);
}

export interface GuardDecision {
  allowed: boolean;
  host: string;
  resolvedIps: string[];
  /** Vetted IP the caller should pin the socket to (anti-rebinding). */
  pinnedIp?: string;
  pinnedFamily?: 4 | 6;
  reason: string;
  /** When blocked: the offending category (loopback/private/…). */
  category?: string;
}

const defaultResolver: Resolver = async (host) => {
  const addrs = await dnsPromises.lookup(host, { all: true, verbatim: true });
  return addrs.map((a) => ({ address: a.address, family: a.family }));
};

/** Hostnames we refuse without even resolving (defense in depth). */
const BLOCKED_NAMES = new Set(['localhost', 'localhost.localdomain', 'ip6-localhost', 'ip6-loopback']);

export async function guardHost(host: string, resolver: Resolver = defaultResolver): Promise<GuardDecision> {
  const lower = host.toLowerCase().replace(/\.$/, '');

  if (!lower) {
    return { allowed: false, host, resolvedIps: [], reason: 'empty host', category: 'invalid' };
  }
  if (BLOCKED_NAMES.has(lower) || lower.endsWith('.localhost')) {
    return { allowed: false, host, resolvedIps: [], reason: `refused: "${host}" is a loopback name`, category: 'loopback' };
  }
  if (lower.endsWith('.internal') || lower.endsWith('.local') || lower.endsWith('.lan')) {
    return { allowed: false, host, resolvedIps: [], reason: `refused: "${host}" is an internal-only domain`, category: 'internal-tld' };
  }

  // IP literal - classify directly, no DNS.
  if (isIpLiteral(host)) {
    const c = classifyIp(host);
    if (!c.public) {
      return { allowed: false, host, resolvedIps: [host], reason: `refused: ${c.reason}`, category: c.category };
    }
    return {
      allowed: true,
      host,
      resolvedIps: [host],
      pinnedIp: host,
      pinnedFamily: c.family,
      reason: `IP literal ${host} is publicly routable`,
    };
  }

  // DNS name - resolve and vet every address.
  let addrs: ResolvedAddr[];
  try {
    addrs = await resolver(host);
  } catch (err) {
    return {
      allowed: false,
      host,
      resolvedIps: [],
      reason: `DNS resolution failed: ${(err as Error).message}`,
      category: 'dns-error',
    };
  }
  if (addrs.length === 0) {
    return { allowed: false, host, resolvedIps: [], reason: 'host did not resolve to any address', category: 'dns-empty' };
  }

  const resolvedIps = addrs.map((a) => a.address);
  for (const a of addrs) {
    const c = classifyIp(a.address);
    if (!c.public) {
      return {
        allowed: false,
        host,
        resolvedIps,
        reason: `refused: ${host} resolves to ${a.address} (${c.reason})`,
        category: c.category,
      };
    }
  }

  const first = addrs[0]!;
  return {
    allowed: true,
    host,
    resolvedIps,
    pinnedIp: first.address,
    pinnedFamily: first.family === 6 ? 6 : 4,
    reason: `${host} resolves only to public addresses (${resolvedIps.join(', ')})`,
  };
}
