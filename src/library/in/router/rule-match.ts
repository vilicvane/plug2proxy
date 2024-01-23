import IPMatching from 'ip-matching';

import {matchHost} from '../../@utils/index.js';
import type {RouteHostMatchRule} from '../../router.js';

import type {GeoLite2} from './geolite2.js';

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
  port: number,
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

  return async (_domain, _port, resolve) => {
    const ip = await resolve();
    return ip !== undefined ? route(ip) : undefined;
  };
}

export function createDomainRuleMatch(pattern: string | string[]): RuleMatch {
  const patterns = Array.isArray(pattern) ? pattern : [pattern];

  return domain => domain !== undefined && matchHost(domain, patterns);
}

export function createPortRuleMatch(port: number | number[]): RuleMatch {
  const portSet = new Set(Array.isArray(port) ? port : [port]);

  return (_domain, port) => portSet.has(port);
}

export function createHostRuleMatch(
  rule: RouteHostMatchRule | RouteHostMatchRule[],
  geolite2: GeoLite2,
): RuleMatch {
  const rules = Array.isArray(rule) ? rule : [rule];

  const matches = rules.map(({ip, geoip, domain, port}) => {
    const and: RuleMatch[] = [];

    if (ip !== undefined) {
      and.push(createIPRuleMatch(ip));
    }

    if (geoip !== undefined) {
      and.push(geolite2.createGeoIPRuleMatch(geoip));
    }

    if (domain !== undefined) {
      and.push(createDomainRuleMatch(domain));
    }

    if (port !== undefined) {
      and.push(createPortRuleMatch(port));
    }

    return and;
  });

  return async function (domain, port, resolve) {
    outer: for (const and of matches) {
      for (const match of and) {
        const result = await match(domain, port, resolve);

        if (result !== true) {
          continue outer;
        }
      }

      return true;
    }

    return false;
  };
}
