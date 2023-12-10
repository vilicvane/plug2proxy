import {readFile, stat, writeFile} from 'fs/promises';
import {buffer} from 'stream/consumers';

import type {CountryResponse} from 'maxmind';
import {Reader} from 'maxmind';
import ms from 'ms';
import {request} from 'undici';
import * as x from 'x-value';

import {
  IN_GEOLITE2_DATABASE_UPDATED,
  IN_GEOLITE2_DATABASE_UPDATE_FAILED,
  IN_GEOLITE2_FAILED_TO_READ_DATABASE,
  Logs,
} from '../../@log/index.js';

import type {RuleMatch} from './rule-match.js';

const MAXMIND_GEO_LITE_2_COUNTRY_DATABASE_URL =
  'https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-Country.mmdb';

const UPDATE_INTERVAL = ms('24h');

const DATABASE_PATH_DEFAULT = 'geolite2.mmdb';

export const GeoLite2Options = x.object({
  /**
   * mmdb 文件保存地址。
   */
  path: x.string.optional(),
});

export type GeoLite2Options = x.TypeOf<typeof GeoLite2Options>;

export class GeoLite2 {
  readonly path: string;

  private readerPromise: Promise<Reader<CountryResponse> | false>;

  private readerResolver:
    | ((reader: Reader<CountryResponse> | false) => void)
    | undefined;

  constructor({path = DATABASE_PATH_DEFAULT}: GeoLite2Options) {
    this.path = path;

    this.readerPromise = new Promise(resolve => {
      this.readerResolver = resolve;
    });

    void this.initialize();
  }

  createGeoIPRuleMatch(match: string | string[]): RuleMatch {
    const matches = Array.isArray(match) ? match : [match];

    const route = async (ips: string[]): Promise<boolean | undefined> => {
      const reader = await this.readerPromise;

      if (!reader) {
        throw new Error('No GeoLite2 database available.');
      }

      if (ips.length === 0) {
        return undefined;
      }

      return ips.some(ip => {
        const region = reader.get(ip)?.country?.iso_code;
        return region ? matches.includes(region) : false;
      });
    };

    return (_domain, resolve) => {
      const ips = resolve();
      return Array.isArray(ips) ? route(ips) : ips.then(route);
    };
  }

  private async initialize(): Promise<void> {
    let firstUpdateAt: number | undefined;

    try {
      const stats = await stat(this.path);

      firstUpdateAt = stats.mtimeMs + UPDATE_INTERVAL;

      const data = await readFile(this.path);

      this.readerResolver!(new Reader(data));
      this.readerResolver = undefined;
    } catch (error) {
      Logs.warn('geolite2', IN_GEOLITE2_FAILED_TO_READ_DATABASE);
    }

    setTimeout(
      () => this.update(),
      firstUpdateAt === undefined ? 0 : Math.max(firstUpdateAt - Date.now(), 0),
    );
  }

  private updateTimer: NodeJS.Timeout | undefined;

  private async update(): Promise<void> {
    clearTimeout(this.updateTimer);

    this.updateTimer = setTimeout(() => void this.update(), UPDATE_INTERVAL);

    let reader: Reader<CountryResponse> | undefined;

    try {
      const response = await request(MAXMIND_GEO_LITE_2_COUNTRY_DATABASE_URL, {
        maxRedirections: 3,
      });

      const data = await buffer(response.body);

      reader = new Reader<CountryResponse>(data);

      await writeFile(this.path, data);

      Logs.info('geolite2', IN_GEOLITE2_DATABASE_UPDATED);
    } catch (error) {
      Logs.error('geolite2', IN_GEOLITE2_DATABASE_UPDATE_FAILED);
      Logs.debug('geolite2', error);
    }

    if (this.readerResolver) {
      // Use false to mark database not available.
      this.readerResolver(reader ?? false);
      this.readerResolver = undefined;
    } else {
      if (reader) {
        this.readerPromise = Promise.resolve(reader);
      }
    }
  }
}
