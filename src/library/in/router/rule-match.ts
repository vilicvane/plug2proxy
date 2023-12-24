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

export function createIPRuleMatch(match: string | string[]): RuleMatch {
  const matches = Array.isArray(match) ? match : [match];

  const ipMatchings = matches
    .reduce((matches, match) => {
      switch (match) {
        case 'private':
          return [...matches, ...PRIVATE_NETWORK_MATCHES];
        case 'loopback':
          return [...matches, ...LOOPBACK_MATCHES];
        default:
          return [...matches, match];
      }
    }, [] as string[])
    .map(match => IPMatching.getMatch(match));

  const route = (ip: string): boolean =>
    ipMatchings.some(ipMatching => ipMatching.matches(ip));

  return async (_domain, resolve) => {
    const ip = await resolve();
    return ip !== undefined ? route(ip) : undefined;
  };
}

export function createDomainRuleMatch(match: string | string[]): RuleMatch {
  const matches = Array.isArray(match) ? match : [match];

  return domain =>
    domain !== undefined && matches.some(match => matchHost(domain, match));
}
