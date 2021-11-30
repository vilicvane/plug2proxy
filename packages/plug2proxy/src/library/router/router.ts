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
      /**
       * 支持 "loopback", "private" 或类似 "10.0.0.0/24" 的格式。
       */
      match: string | string[];
    }
  | {
      type: 'geoip';
      /**
       * 支持 MaxMind GeoLite2 数据中的 country.iso_code 字段，如 "CN"。需要下载并配置
       * 数据库文件，见下方 `geoIPDatabase` 参数。
       */
      match: string | string[];
    }
  | {
      type: 'domain';
      /**
       * 域名，支持 micromatch 格式。如 ["baidu.com", "*.baidu.com"]。
       */
      match: string | string[];
    }
) & {
  /**
   * 是否反向匹配。
   */
  negate?: boolean;
  /**
   * 路由名称，配合 Plug2Proxy `Client` 使用时仅支持 'proxy' 和 'direct'。
   */
  route: string;
};

export interface RouterOptions {
  /**
   * 路由规则。
   */
  rules: RouterRule[];
  /**
   * 默认路由名称，配合 Plug2Proxy `Client` 使用时仅支持 'proxy' 和 'direct'。
   */
  fallback: string;
  /**
   * 路由匹配缓存时间（毫秒）。
   */
  cacheExpiration?: number;
  /**
   * MaxMind GeoLite2 国家数据库文件地址（mmdb 格式）。
   */
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
            switch (match) {
              case 'private':
                return [
                  ...matches,
                  '10.0.0.0/8',
                  '172.16.0.0/12',
                  '192.168.0.0/16',
                ];
              case 'loopback':
                return [...matches, '127.0.0.0/8'];

              default:
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
