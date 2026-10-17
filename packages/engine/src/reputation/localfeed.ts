import type { ReputationResult } from '@argus/shared';
import type { ReputationProvider } from './provider.ts';

const BAD_HOSTS = new Map<string, string>([
  ['testsafebrowsing.appspot.com', "Google's official Safe Browsing test site"],
  ['malware.testing.google.test', "Google's malware-test hostname"],
  ['phishing-demo.argus.test', 'Argus bundled phishing demo host'],
  ['secure-paypa1-login.tk', 'Argus bundled phishing demo host'],
]);

const BAD_HASHES = new Map<string, string>([
  ['275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f', 'EICAR-STANDARD-ANTIVIRUS-TEST-FILE'],
]);

function hostOf(url: string): string | undefined {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return undefined;
  }
}

export function localFeedProvider(): ReputationProvider {
  return {
    name: 'Local sample feed',
    configured: true,
    async checkUrl(url): Promise<ReputationResult> {
      const host = hostOf(url);
      const note = host ? BAD_HOSTS.get(host) : undefined;
      return {
        provider: 'Local sample feed',
        available: true,
        listed: !!note,
        categories: note ? ['malware/phishing'] : undefined,
        detail: note ?? 'not present in the bundled sample feed',
        source: 'local-feed',
      };
    },
    async checkHash(sha256): Promise<ReputationResult> {
      const note = BAD_HASHES.get(sha256.toLowerCase());
      return {
        provider: 'Local sample feed',
        available: true,
        listed: !!note,
        categories: note ? ['test-file'] : undefined,
        detail: note ?? 'not present in the bundled sample feed',
        source: 'local-feed',
      };
    },
  };
}
