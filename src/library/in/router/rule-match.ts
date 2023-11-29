import * as IPMatching from 'ip-matching';
import {minimatch} from 'minimatch';

const LOOPBACK_MATCHES = ['127.0.0.0/8', '::1'];

const PRIVATE_NETWORK_MATCHES = [
  ...LOOPBACK_MATCHES,
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
];

export type RuleMatch = (
  domain: string | undefined,
  resolve: () => Promise<string[]> | string[],
) => Promise<boolean> | boolean;

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

  const route = (ips: string[]): boolean =>
    ipMatchings.some(ipMatching => ips.some(ip => ipMatching.matches(ip)));

  return async (_domain, resolve) => {
    const ips = await resolve();
    return route(ips);
  };
}

export function createDomainRuleMatch(match: string | string[]): RuleMatch {
  const matches = Array.isArray(match) ? match : [match];

  return domain =>
    domain !== undefined && matches.some(match => minimatch(domain, match));
}
