

import net from 'node:net';

export interface IpClassification {
  ip: string;
  family: 4 | 6;

  public: boolean;

  category: string;

  reason: string;
}




export function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const o = Number(p);
    if (o > 255) return null;
    n = (n << 8) | o;
  }
  return n >>> 0;
}

interface V4Range {
  base: number;
  prefix: number;
  category: string;
  reason: string;
}

function v4(cidr: string, category: string, reason: string): V4Range {
  const [addr, pfx] = cidr.split('/');
  return { base: ipv4ToInt(addr!)!, prefix: Number(pfx), category, reason };
}


const V4_SPECIAL: V4Range[] = [
  v4('0.0.0.0/8', 'this-network', '"this host" range (0.0.0.0/8)'),
  v4('10.0.0.0/8', 'private', 'RFC-1918 private network (10/8)'),
  v4('100.64.0.0/10', 'cgnat', 'carrier-grade NAT (100.64/10)'),
  v4('127.0.0.0/8', 'loopback', 'loopback (127/8)'),
  v4('169.254.0.0/16', 'link-local', 'link-local - includes cloud metadata 169.254.169.254'),
  v4('172.16.0.0/12', 'private', 'RFC-1918 private network (172.16/12)'),
  v4('192.0.0.0/24', 'reserved', 'IETF protocol assignments (192.0.0/24)'),
  v4('192.0.2.0/24', 'documentation', 'TEST-NET-1 documentation range'),
  v4('192.88.99.0/24', 'reserved', '6to4 relay anycast (192.88.99/24)'),
  v4('192.168.0.0/16', 'private', 'RFC-1918 private network (192.168/16)'),
  v4('198.18.0.0/15', 'benchmark', 'network benchmark range (198.18/15)'),
  v4('198.51.100.0/24', 'documentation', 'TEST-NET-2 documentation range'),
  v4('203.0.113.0/24', 'documentation', 'TEST-NET-3 documentation range'),
  v4('224.0.0.0/4', 'multicast', 'multicast (224/4)'),
  v4('240.0.0.0/4', 'reserved', 'reserved/future use (240/4)'),
];

function v4InRange(ip: number, r: V4Range): boolean {
  if (r.prefix === 0) return true;
  const mask = (0xffffffff << (32 - r.prefix)) >>> 0;
  return (ip & mask) >>> 0 === (r.base & mask) >>> 0;
}

function classifyV4(ip: string): IpClassification {
  const n = ipv4ToInt(ip);
  if (n === null) {
    return { ip, family: 4, public: false, category: 'invalid', reason: 'unparseable IPv4' };
  }
  if (n === 0xffffffff) {
    return { ip, family: 4, public: false, category: 'broadcast', reason: 'limited broadcast 255.255.255.255' };
  }
  for (const r of V4_SPECIAL) {
    if (v4InRange(n, r)) {
      return { ip, family: 4, public: false, category: r.category, reason: r.reason };
    }
  }
  return { ip, family: 4, public: true, category: 'public', reason: 'publicly-routable unicast' };
}




export function ipv6ToBigInt(ip: string): bigint | null {
  if (net.isIPv6(ip) === false) return null;
  let str = ip;

  const pct = str.indexOf('%');
  if (pct !== -1) str = str.slice(0, pct);


  let tailHextets: string[] = [];
  const lastColon = str.lastIndexOf(':');
  const tail = str.slice(lastColon + 1);
  if (tail.includes('.')) {
    const v4 = ipv4ToInt(tail);
    if (v4 === null) return null;
    tailHextets = [((v4 >>> 16) & 0xffff).toString(16), (v4 & 0xffff).toString(16)];
    str = str.slice(0, lastColon + 1) + tailHextets.join(':');
  }

  const halves = str.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tailParts = halves.length === 2 ? (halves[1] ? halves[1].split(':') : []) : null;

  let hextets: string[];
  if (tailParts === null) {
    hextets = head;
  } else {
    const missing = 8 - head.length - tailParts.length;
    if (missing < 0) return null;
    hextets = [...head, ...Array(missing).fill('0'), ...tailParts];
  }
  if (hextets.length !== 8) return null;

  let n = 0n;
  for (const h of hextets) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(h)) return null;
    n = (n << 16n) | BigInt(parseInt(h, 16));
  }
  return n;
}

interface V6Range {
  base: bigint;
  prefix: number;
  category: string;
  reason: string;
}

function v6(cidr: string, category: string, reason: string): V6Range {
  const [addr, pfx] = cidr.split('/');
  return { base: ipv6ToBigInt(addr!)!, prefix: Number(pfx), category, reason };
}

const V6_SPECIAL: V6Range[] = [
  v6('::1/128', 'loopback', 'IPv6 loopback (::1)'),
  v6('::/128', 'unspecified', 'unspecified address (::)'),
  v6('100::/64', 'discard', 'discard-only block (100::/64)'),
  v6('2001:db8::/32', 'documentation', 'documentation range (2001:db8::/32)'),
  v6('fc00::/7', 'unique-local', 'unique local address (fc00::/7)'),
  v6('fe80::/10', 'link-local', 'IPv6 link-local (fe80::/10)'),
  v6('ff00::/8', 'multicast', 'IPv6 multicast (ff00::/8)'),
];

function v6InRange(ip: bigint, r: V6Range): boolean {
  if (r.prefix === 0) return true;
  const shift = BigInt(128 - r.prefix);
  return ip >> shift === r.base >> shift;
}


const V4_MAPPED_SIG = ipv6ToBigInt('::ffff:0:0')! >> 32n;
const NAT64_SIG = ipv6ToBigInt('64:ff9b::')! >> 32n;

function classifyV6(ip: string): IpClassification {
  const n = ipv6ToBigInt(ip);
  if (n === null) {
    return { ip, family: 6, public: false, category: 'invalid', reason: 'unparseable IPv6' };
  }

  const high96 = n >> 32n;
  if (high96 === V4_MAPPED_SIG || high96 === NAT64_SIG) {
    const v4int = Number(n & 0xffffffffn) >>> 0;
    const dotted = [(v4int >>> 24) & 255, (v4int >>> 16) & 255, (v4int >>> 8) & 255, v4int & 255].join('.');
    const inner = classifyV4(dotted);
    return {
      ip,
      family: 6,
      public: inner.public,
      category: inner.public ? 'v4-embedded' : inner.category,
      reason: `embeds IPv4 ${dotted} - ${inner.reason}`,
    };
  }
  for (const r of V6_SPECIAL) {
    if (v6InRange(n, r)) {
      return { ip, family: 6, public: false, category: r.category, reason: r.reason };
    }
  }
  return { ip, family: 6, public: true, category: 'public', reason: 'publicly-routable unicast' };
}




export function classifyIp(ip: string): IpClassification {
  const fam = net.isIP(ip);
  if (fam === 4) return classifyV4(ip);
  if (fam === 6) return classifyV6(ip);
  return { ip, family: 4, public: false, category: 'invalid', reason: 'not an IP address' };
}

export function isPublicIp(ip: string): boolean {
  return classifyIp(ip).public;
}


export function isIpLiteral(host: string): boolean {
  return net.isIP(host) !== 0;
}
