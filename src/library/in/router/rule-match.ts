import IPMatching from 'ip-matching';

import {matchHost} from '../../@utils/index.js';

const LOOPBACK_MATCHES = ['127.0.0.0/8', '::1'];

const PRIVATE_NETWORK_MATCHES = [
  ...LOOPBACK_MATCHES,
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  'fc00::/7',
  'fe80::/10',
];

export type RuleMatch = (
  domain: string | undefined,
  resolve: () => Promise<string | undefined>,
) => Promise<boolean | undefined> | boolean | undefined;

export function createIPRuleMatch(pattern: string | string[]): RuleMatch {
  const patterns = Array.isArray(pattern) ? pattern : [pattern];

  const ipMatchings = patterns
    .reduce((patterns, pattern) => {
      switch (pattern) {
        case 'private':
          return [...patterns, ...PRIVATE_NETWORK_MATCHES];
        case 'loopback':
          return [...patterns, ...LOOPBACK_MATCHES];
        default:
          return [...patterns, pattern];
      }
    }, [] as string[])
    .map(pattern => IPMatching.getMatch(pattern));

  const route = (ip: string): boolean =>
    ipMatchings.some(ipMatching => ipMatching.matches(ip));

  return async (_domain, resolve) => {
    const ip = await resolve();
    return ip !== undefined ? route(ip) : undefined;
  };
}

export function createDomainRuleMatch(pattern: string | string[]): RuleMatch {
  const patterns = Array.isArray(pattern) ? pattern : [pattern];

  return domain => domain !== undefined && matchHost(domain, patterns);
}
