import assert from 'assert';
import {randomInt} from 'crypto';
import * as DNS from 'dns/promises';
import * as Net from 'net';

import {IN_ROUTER_FAILED_TO_RESOLVE_DOMAIN, Logs} from '../../@log/index.js';
import {getURLPort} from '../../@utils/index.js';
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
  createPortRuleMatch,
} from './rule-match.js';

export class Router {
  private candidateMap = new Map<TunnelId, RouteCandidate>();

  private directRules: {
    match: RuleMatch;
    negate: boolean;
  }[];

  constructor(
    readonly geolite2: GeoLite2,
    direct: RouteMatchRule[] | undefined,
  ) {
    this.directRules = (direct ?? []).map(rule => {
      return {
        match: this.createMatchFunction(rule),
        negate: rule.negate ?? false,
      };
    });
  }

  register(
    id: TunnelId,
    remote: string,
    routeMatchOptions: RouteMatchOptions,
  ): void {
    this.candidateMap.set(id, {
      tunnel: id,
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

  async routeHost(
    hostname: string,
    port: number,
    resolveIP = true,
  ): Promise<RouteCandidate | undefined> {
    let domain: string | undefined;
    let resolvedIPPromise: Promise<string | undefined> | undefined;

    if (Net.isIP(hostname)) {
      resolvedIPPromise = Promise.resolve(hostname);
    } else {
      domain = hostname;

      if (!resolveIP) {
        resolvedIPPromise = Promise.resolve(undefined);
      }
    }

    const resolve = (): Promise<string | undefined> =>
      resolvedIPPromise ??
      (resolvedIPPromise = DNS.lookup(domain!).then(
        result => result.address,
        () => {
          Logs.warn('router', IN_ROUTER_FAILED_TO_RESOLVE_DOMAIN(domain!));
          return undefined;
        },
      ));

    for (const {match, negate} of this.directRules) {
      let matched = await match(domain, port, resolve);

      if (matched === undefined) {
        continue;
      }

      if (negate) {
        matched = !matched;
      }

      if (matched) {
        return undefined;
      }
    }

    let highestPriority = -Infinity;
    let priorCandidates: RouteCandidate[] = [];

    for (const candidate of this.candidateMap.values()) {
      const priority = await match(
        domain,
        port,
        resolve,
        candidate.routeMatchOptions,
      );

      if (priority === false || priority < highestPriority) {
        continue;
      }

      if (priority > highestPriority) {
        highestPriority = priority;
        priorCandidates = [candidate];
      } else {
        priorCandidates.push(candidate);
      }
    }

    return priorCandidates.length > 0
      ? priorCandidates[randomInt(priorCandidates.length)]
      : undefined;
  }

  routeURL(url: string): Promise<RouteCandidate | undefined> {
    const urlObject = new URL(url);

    const port = getURLPort(urlObject);

    return this.routeHost(urlObject.hostname, port);
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
      case 'all':
        return () => true;
      case 'domain':
        return createDomainRuleMatch(match.match);
      case 'ip':
        return createIPRuleMatch(match.match);
      case 'port':
        return createPortRuleMatch(match.match);
      case 'geoip':
        return this.geolite2.createGeoIPRuleMatch(match.match);
    }
  }
}

export type RouteCandidate = {
  tunnel: TunnelId;
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
  port: number,
  resolve: () => Promise<string | undefined>,
  {include, exclude, priority: priorityDefault}: InitializedRouteMatchOptions,
): Promise<number | false> {
  for (const {match, negate} of exclude) {
    let matched = await match(domain, port, resolve);

    if (matched === undefined) {
      continue;
    }

    if (negate) {
      matched = !matched;
    }

    if (matched) {
      return false;
    }
  }

  let highestPriority: number | undefined;

  for (const {match, negate, priority = priorityDefault} of include) {
    let matched = await match(domain, port, resolve);

    if (matched === undefined) {
      continue;
    }

    if (negate) {
      matched = !matched;
    }

    if (matched) {
      highestPriority =
        highestPriority !== undefined
          ? Math.max(highestPriority, priority)
          : priority;
    }
  }

  return highestPriority ?? false;
}
