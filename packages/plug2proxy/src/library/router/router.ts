import {promises as DNS} from 'dns';
import * as FS from 'fs';
import {isIP} from 'net';

import {CountryResponse, Reader} from 'maxmind';
import micromatch from 'micromatch';
import {Netmask} from 'netmask';

const CACHE_EXPIRATION_DEFAULT = 10 * 60_000;

export type RouterRule = (
  | {
      type: 'ip';
      match: string | string[];
    }
  | {
      type: 'geoip';
      match: string | string[];
    }
  | {
      type: 'domain';
      match: string | string[];
    }
) & {
  negate?: boolean;
  route: string;
};

export interface RouterOptions {
  rules: RouterRule[];
  fallback: string;
  cacheExpiration?: number;
  geoIPDatabase?: string;
}

export class Router {
  private routeCacheMap = new Map<string, [route: string, expiresAt: number]>();
  private routingMap = new Map<string, Promise<string>>();

  private maxmindReader: Reader<CountryResponse> | undefined;

  constructor(readonly options: RouterOptions) {
    this.maxmindReader = options.geoIPDatabase
      ? new Reader(FS.readFileSync(options.geoIPDatabase))
      : undefined;
  }

  async route(host: string): Promise<string> {
    let {cacheExpiration = CACHE_EXPIRATION_DEFAULT} = this.options;

    let routeCacheMap = this.routeCacheMap;
    let routingMap = this.routingMap;

    let now = Date.now();

    let cache = routeCacheMap.get(host);

    if (cache) {
      let [route, expiresAt] = cache;

      if (now < expiresAt) {
        return route;
      }
    }

    let routing = routingMap.get(host);

    if (!routing) {
      routing = this._route(host)
        .then(route => {
          routeCacheMap.set(host, [route, now + cacheExpiration]);
          return route;
        })
        .finally(() => {
          routingMap.delete(host);
        });
    }

    return routing;
  }

  private async _route(host: string): Promise<string> {
    let {rules, fallback} = this.options;

    let maxmindReader = this.maxmindReader;

    let domain: string | undefined;
    let ips: string[] | undefined;

    if (isIP(host)) {
      ips = [host];
    } else {
      domain = host;
    }

    for (let {negate = false, route, ...rest} of rules) {
      let matched: boolean;

      switch (rest.type) {
        case 'ip': {
          let {match} = rest;

          if (typeof match === 'string') {
            match = [match];
          }

          match = match.reduce((matches, match) => {
            if (match === 'private') {
              return [
                ...matches,
                '10.0.0.0/8',
                '172.16.0.0/12',
                '192.168.0.0/16',
              ];
            } else {
              return [...matches, match];
            }
          }, [] as string[]);

          let netmasks = match.map(value => new Netmask(value));

          if (!ips) {
            try {
              ips = await DNS.resolve(host);
            } catch (error) {
              continue;
            }
          }

          matched = netmasks.some(netmask =>
            ips!.some(ip => netmask.contains(ip)),
          );

          break;
        }
        case 'geoip': {
          if (!maxmindReader) {
            matched = false;
            continue;
          }

          let {match} = rest;

          if (typeof match === 'string') {
            match = [match];
          }

          if (!ips) {
            try {
              ips = await DNS.resolve(host);
            } catch (error) {
              continue;
            }
          }

          matched = ips.some(ip => {
            let region = maxmindReader!.get(ip)?.country?.iso_code;
            return !!region && (match as string[]).includes(region);
          });

          break;
        }
        case 'domain': {
          if (!domain) {
            continue;
          }

          matched = micromatch.contains(domain, rest.match);
          break;
        }
      }

      if (negate) {
        matched = !matched;
      }

      if (matched) {
        return route;
      }
    }

    return fallback;
  }
}
