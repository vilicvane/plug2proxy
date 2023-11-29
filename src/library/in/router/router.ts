import * as DNS from 'dns';
import * as Net from 'net';

import {
  ROUTE_MATCH_PRIORITY_DEFAULT,
  ROUTE_MATCH_RULE_NEGATE_DEFAULT,
  type RouteMatchIncludeRule,
  type RouteMatchOptions,
  type RouteMatchRule,
} from '../../router.js';
import type {TunnelCandidateId} from '../tunnel.js';

import type {GeoLite2} from './geolite2.js';
import {
  type RuleMatch,
  createDomainRuleMatch,
  createIPRuleMatch,
} from './rule-match.js';

export class Router {
  private optionsMap = new Map<
    TunnelCandidateId,
    InitializedRouteMatchOptions
  >();

  constructor(readonly geolite2: GeoLite2) {}

  register(
    id: TunnelCandidateId,
    {
      include = [],
      exclude = [],
      priority = ROUTE_MATCH_PRIORITY_DEFAULT,
    }: RouteMatchOptions,
  ): () => void {
    this.optionsMap.set(id, {
      include: include.map(rule => {
        return {
          match: this.createMatchFunction(rule),
          negate: rule.negate ?? ROUTE_MATCH_RULE_NEGATE_DEFAULT,
          priority: rule.priority ?? priority,
        };
      }),
      exclude: exclude.map(rule => {
        return {
          match: this.createMatchFunction(rule),
          negate: rule.negate ?? ROUTE_MATCH_RULE_NEGATE_DEFAULT,
        };
      }),
      priority,
    });

    return () => {
      this.optionsMap.delete(id);
    };
  }

  async route(host: string): Promise<Route | undefined> {
    let domain: string | undefined;
    let ips: string[] | undefined;

    if (Net.isIP(host)) {
      ips = [host];
    } else {
      domain = host;
    }

    const resolve = (): Promise<string[]> | string[] =>
      ips ??
      DNS.promises.resolve(domain!).then(resolvedIPs => {
        ips = resolvedIPs;
        return ips;
      });

    for (const [id, routeMatchOptions] of this.optionsMap) {
      const priority = await match(domain, resolve, routeMatchOptions);

      if (priority !== false) {
        return {
          id,
        };
      }
    }

    return undefined;
  }

  routeReferer(referer: string): Promise<Route | undefined> {
    const host = new URL(referer).host;
    return this.route(host);
  }

  private createMatchFunction(match: RouteMatchRule): RuleMatch {
    switch (match.type) {
      case 'domain':
        return createDomainRuleMatch(match.match);
      case 'ip':
        return createIPRuleMatch(match.match);
      case 'geoip':
        return this.geolite2.createGeoIPRuleMatch(match.match);
    }
  }
}

export type Route = {
  id: TunnelCandidateId;
};

type InitializedRouteMatchOptions = {
  include: {
    match: RuleMatch;
    negate: boolean;
    priority: number | undefined;
  }[];
  exclude: {
    match: RuleMatch;
    negate: boolean;
  }[];
  priority: number;
};

async function match(
  domain: string | undefined,
  resolve: () => Promise<string[]> | string[],
  {include, exclude, priority: priorityDefault}: InitializedRouteMatchOptions,
): Promise<number | false> {
  for (const {match, negate} of exclude) {
    let matched = await match(domain, resolve);

    if (negate) {
      matched = !matched;
    }

    if (matched) {
      return false;
    }
  }

  for (const {match, negate, priority = priorityDefault} of include) {
    let matched = await match(domain, resolve);

    if (negate) {
      matched = !matched;
    }

    if (matched) {
      return priority;
    }
  }

  return false;
}
