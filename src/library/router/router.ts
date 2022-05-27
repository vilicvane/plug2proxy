import * as DNS from 'dns';
import * as FS from 'fs';
import * as HTTPS from 'https';
import * as Net from 'net';
import * as Path from 'path';
import * as ZLib from 'zlib';

import * as IPMatching from 'ip-matching';
import * as MaxMind from 'maxmind';
import * as MicroMatch from 'micromatch';
import * as TarStream from 'tar-stream';
import * as x from 'x-value';

import {IPMatchPattern} from '../@x-types';

const LOOPBACK_MATCHES = ['127.0.0.0/8', '::1'];

const PRIVATE_NETWORK_MATCHES = [
  ...LOOPBACK_MATCHES,
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
];

const GEOLITE2_UPDATE_INTERVAL = 24 * 3600_000;

const FALLBACK_DEFAULT = 'direct';
const CACHE_EXPIRATION_DEFAULT = 10 * 60_000;

function MAXMIND_GEO_LITE_2_COUNTRY_DATABASE_URL(licenseKey: string): string {
  return `https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=${encodeURIComponent(
    licenseKey,
  )}&suffix=tar.gz`;
}

const GEOLITE2_PATH_DEFAULT = 'geolite2.mmdb';

const Route = x.union(x.literal('direct'), x.literal('proxy'));

export const RouterRule = x.intersection(
  x.union(
    x.object({
      type: x.literal('ip'),
      /**
       * 支持 "loopback", "private" 或类似 "10.0.0.0/24" 的格式。
       */
      match: x.union(
        x.literal('loopback'),
        x.literal('private'),
        IPMatchPattern,
        x.array(IPMatchPattern),
      ),
    }),
    x.object({
      type: x.literal('geoip'),
      /**
       * 支持 MaxMind GeoLite2 数据中的 country.iso_code 字段，如 "CN"。需要下载并配置
       * 数据库文件，见下方 `geoIPDatabase` 参数。
       */
      match: x.union(x.string, x.array(x.string)),
    }),
    x.object({
      type: x.literal('domain'),
      /**
       * 域名，支持 micromatch 格式。如 ["baidu.com", "*.baidu.com"]。
       */
      match: x.union(x.string, x.array(x.string)),
    }),
  ),
  x.object({
    /**
     * 是否反向匹配。
     */
    negate: x.boolean.optional(),
    /**
     * 路由名称，配合 Plug2Proxy `Client` 使用时仅支持 'proxy' 和 'direct'。
     */
    route: Route,
  }),
);

export type RouterRule = x.TypeOf<typeof RouterRule>;

export const RouterOptions = x.object({
  /**
   * 路由规则。
   */
  rules: x.array(RouterRule).optional(),
  /**
   * 默认路由名称，配合 Plug2Proxy `Client` 使用时仅支持 'proxy' 和 'direct'。
   */
  fallback: Route.optional(),
  /**
   * 路由匹配缓存时间（毫秒）。
   */
  cacheExpiration: x.number.optional(),
  /**
   * MaxMind GeoLite2（Country）配置，用于 geoip 规则。
   */
  geolite2: x
    .object({
      /**
       * mmdb 文件地址。
       */
      path: x.string.optional(),
      /**
       * MaxMind License Key，填写后每日更新。
       * @see https://support.maxmind.com/hc/en-us/articles/4407111582235-Generate-a-License-Key
       */
      licenseKey: x.string.optional(),
    })
    .optional(),
});

export type RouterOptions = x.TypeOf<typeof RouterOptions>;

export class Router {
  private routeCacheMap = new Map<string, [route: string, expiresAt: number]>();
  private routingMap = new Map<string, Promise<string>>();

  private fallback: string;

  private cacheExpiration: number;

  private geolite2Path: string;
  private geolite2LicenseKey: string | undefined;

  private maxmindReader: MaxMind.Reader<MaxMind.CountryResponse> | undefined;

  readonly rulesPromise: Promise<Rule[]>;

  constructor({
    rules = [],
    fallback = FALLBACK_DEFAULT,
    cacheExpiration = CACHE_EXPIRATION_DEFAULT,
    geolite2: {
      path: geolite2Path = GEOLITE2_PATH_DEFAULT,
      licenseKey: geolite2LicenseKey,
    } = {},
  }: RouterOptions) {
    this.fallback = fallback;
    this.geolite2Path = Path.resolve(geolite2Path);
    this.geolite2LicenseKey = geolite2LicenseKey;
    this.cacheExpiration = cacheExpiration;

    this.rulesPromise = this.initialize(rules);
  }

  async route(host: string): Promise<string> {
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
          routeCacheMap.set(host, [route, now + this.cacheExpiration]);
          return route;
        })
        .finally(() => {
          routingMap.delete(host);
        });
    }

    return routing;
  }

  private async _route(host: string): Promise<string> {
    let rules = await this.rulesPromise;

    let domain: string | undefined;
    let ips: string[] | undefined;

    if (Net.isIP(host)) {
      ips = [host];
    } else {
      domain = host;
    }

    let resolve = (): Promise<string[]> | string[] =>
      ips ??
      DNS.promises.resolve(domain!).then(resolvedIPs => {
        ips = resolvedIPs;
        return ips;
      });

    for (let {match, negate = false, route} of rules) {
      let matched = match(domain, resolve);

      if (typeof matched !== 'boolean') {
        matched = await matched;
      }

      if (negate) {
        matched = !matched;
      }

      if (matched) {
        return route;
      }
    }

    return this.fallback;
  }

  private async initialize(rules: RouterRule[]): Promise<Rule[]> {
    let geoLite2Path = this.geolite2Path;

    if (geoLite2Path) {
      try {
        let stats = await FS.promises.stat(geoLite2Path);
        let data = await FS.promises.readFile(geoLite2Path);

        this.maxmindReader = new MaxMind.Reader(data);

        this.scheduleGeoLite2Update(
          Math.max(GEOLITE2_UPDATE_INTERVAL - (Date.now() - stats.mtimeMs), 0),
        );
      } catch {
        await this.updateGeoLite2();

        this.scheduleGeoLite2Update();
      }
    }

    return rules.map(rule => {
      switch (rule.type) {
        case 'ip':
          return {
            ...rule,
            match: createIPRuleMatch(rule.match),
          };
        case 'geoip':
          if (!this.maxmindReader) {
            throw new Error(
              'Using geoip rule requires valid GeoLite2 options configured',
            );
          }

          return {
            ...rule,
            match: createGeoIPRuleMatch(rule.match, () => this.maxmindReader!),
          };
        case 'domain':
          return {
            ...rule,
            match: createDomainRuleMatch(rule.match),
          };
      }
    });
  }

  private async updateGeoLite2(): Promise<void> {
    let geoLite2LicenseKey = this.geolite2LicenseKey;

    if (!geoLite2LicenseKey) {
      return;
    }

    return new Promise<void>((resolve, reject) => {
      HTTPS.get(
        MAXMIND_GEO_LITE_2_COUNTRY_DATABASE_URL(geoLite2LicenseKey!),
        response => {
          response
            .pipe(ZLib.createGunzip())
            .on('error', reject)
            .pipe(TarStream.extract())
            .on('error', reject)
            .on('entry', (headers, stream, next) => {
              if (!headers.name.endsWith('.mmdb')) {
                next();
                return;
              }

              let data: Buffer[] = [];

              stream
                .on('data', buffer => {
                  data.push(buffer);
                })
                .pipe(FS.createWriteStream(this.geolite2Path))
                .on('error', error => {
                  reject(error);
                  next();
                })
                .on('finish', () => {
                  this.maxmindReader = new MaxMind.Reader(Buffer.concat(data));
                  resolve();
                });
            });
        },
      ).on('error', reject);
    }).then(
      () => console.info('geolite2 updated.'),
      error => {
        console.error('geolite2 update error:', error.message);
        throw error;
      },
    );
  }

  private scheduleGeoLite2Update(delay = GEOLITE2_UPDATE_INTERVAL): void {
    if (!this.geolite2LicenseKey) {
      return;
    }

    setTimeout(() => {
      this.updateGeoLite2().then(
        () => this.scheduleGeoLite2Update(),
        () => this.scheduleGeoLite2Update(),
      );
    }, delay);
  }
}

type RuleMatch = (
  domain: string | undefined,
  resolve: () => Promise<string[]> | string[],
) => Promise<boolean> | boolean;

type Rule = Omit<RouterRule, 'match'> & {match: RuleMatch};

function createIPRuleMatch(match: string | string[]): RuleMatch {
  if (typeof match === 'string') {
    match = [match];
  }

  let ipMatchings = match
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

  let route = (ips: string[]): boolean =>
    ipMatchings.some(ipMatching => ips.some(ip => ipMatching.matches(ip)));

  return (_domain, resolve) => {
    let ips = resolve();
    return Array.isArray(ips) ? route(ips) : ips.then(route);
  };
}

function createGeoIPRuleMatch(
  match: string | string[],
  getReader: () => MaxMind.Reader<MaxMind.CountryResponse>,
): RuleMatch {
  if (typeof match === 'string') {
    match = [match];
  }

  let route = (ips: string[]): boolean => {
    return ips.some(ip => {
      let region = getReader().get(ip)?.country?.iso_code;
      return region ? match.includes(region) : false;
    });
  };

  return (_domain, resolve) => {
    let ips = resolve();
    return Array.isArray(ips) ? route(ips) : ips.then(route);
  };
}

function createDomainRuleMatch(match: string | string[]): RuleMatch {
  return domain => !!domain && MicroMatch.isMatch(domain, match);
}
