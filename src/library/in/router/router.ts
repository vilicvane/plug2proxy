import assert from 'assert';
import * as DNS from 'dns';
import * as Net from 'net';

import type {TunnelId} from '../../common.js';
import {
  ROUTE_MATCH_PRIORITY_DEFAULT,
  ROUTE_MATCH_RULE_NEGATE_DEFAULT,
  type RouteMatchOptions,
  type RouteMatchRule,
} from '../../router.js';

import type {GeoLite2} from './geolite2.js';
import {
  type RuleMatch,
  createDomainRuleMatch,
  createIPRuleMatch,
} from './rule-match.js';

export class Router {
  private candidateMap = new Map<TunnelId, RouteCandidate>();

  constructor(readonly geolite2: GeoLite2) {}

  register(
    id: TunnelId,
    remote: string,
    routeMatchOptions: RouteMatchOptions,
  ): void {
    this.candidateMap.set(id, {
      id,
      remote,
      routeMatchOptions: this.initializeRouteMatchOptions(routeMatchOptions),
    });
  }

  unregister(id: TunnelId): void {
    this.candidateMap.delete(id);
  }

  update(id: TunnelId, routeMatchOptions: RouteMatchOptions): void {
    const candidate = this.candidateMap.get(id);

    assert(candidate);

    candidate.routeMatchOptions =
      this.initializeRouteMatchOptions(routeMatchOptions);
  }

  async route(host: string): Promise<TunnelId | undefined> {
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

    for (const [id, {routeMatchOptions}] of this.candidateMap) {
      const priority = await match(domain, resolve, routeMatchOptions);

      if (priority !== false) {
        return id;
      }
    }

    return undefined;
  }

  routeReferer(referer: string): Promise<TunnelId | undefined> {
    const host = new URL(referer).host;
    return this.route(host);
  }

  private initializeRouteMatchOptions({
    include = [],
    exclude = [],
    priority = ROUTE_MATCH_PRIORITY_DEFAULT,
  }: RouteMatchOptions): InitializedRouteMatchOptions {
    return {
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
    };
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

export type RouteCandidate = {
  id: TunnelId;
  remote: string;
  routeMatchOptions: InitializedRouteMatchOptions;
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