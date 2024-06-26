import {once} from 'events';
import {readFile, stat, writeFile} from 'fs/promises';
import type * as HTTP from 'http';
import * as HTTPS from 'https';
import type {Duplex} from 'stream';
import {buffer} from 'stream/consumers';
import * as TLS from 'tls';

import type {CountryResponse} from 'maxmind';
import {Reader} from 'maxmind';
import ms from 'ms';

import {
  IN_GEOLITE2_DATABASE_UPDATED,
  IN_GEOLITE2_DATABASE_UPDATE_FAILED,
  IN_GEOLITE2_FAILED_TO_READ_DATABASE,
  Logs,
} from '../../@log/index.js';
import {getURLPort} from '../../@utils/index.js';
import type {TunnelServer} from '../tunnel-server.js';

import type {RuleMatch} from './rule-match.js';

const MAXMIND_GEO_LITE_2_COUNTRY_DATABASE_URL =
  'https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-Country.mmdb';

const UPDATE_INTERVAL = ms('24h');

export type GeoLite2Options = {
  path: string;
};

export class GeoLite2 {
  readonly path: string;

  tunnelServer!: TunnelServer;

  private readerPromise: Promise<Reader<CountryResponse> | false>;

  /**
   * Will be set to `undefined` after the first successful loading (from either
   * saved file or update).
   */
  private readerResolver:
    | ((reader: Reader<CountryResponse> | false) => void)
    | undefined;

  constructor({path}: GeoLite2Options) {
    this.path = path;

    this.readerPromise = new Promise(resolve => {
      this.readerResolver = resolve;
    });
  }

  createGeoIPRuleMatch(pattern: string | string[]): RuleMatch {
    const matches = Array.isArray(pattern) ? pattern : [pattern];

    const route = async (ip: string): Promise<boolean | undefined> => {
      void this.initializeOrUpdate();

      const reader = await this.readerPromise;

      if (!reader) {
        throw new Error('No GeoLite2 database available.');
      }

      const region = reader.get(ip)?.country?.iso_code;

      return region !== undefined ? matches.includes(region) : false;
    };

    return async (_domain, _port, resolve) => {
      const ip = await resolve();
      return ip !== undefined ? route(ip) : undefined;
    };
  }

  private updating = false;

  private updatedAt = 0;

  private get outdated(): boolean {
    return this.updatedAt + UPDATE_INTERVAL < Date.now();
  }

  private initializeCalled = false;

  private async initializeOrUpdate(): Promise<void> {
    if (this.updating) {
      return;
    }

    try {
      this.updating = true;

      if (this.initializeCalled) {
        if (this.outdated) {
          await this.update();
        }
      } else {
        this.initializeCalled = true;

        await this.initialize();
      }
    } finally {
      this.updating = false;
    }
  }

  private async initialize(): Promise<void> {
    try {
      const stats = await stat(this.path);

      const data = await readFile(this.path);

      this.readerResolver!(new Reader(data));
      this.readerResolver = undefined;

      this.updatedAt = stats.mtimeMs;
    } catch (error) {
      Logs.warn('geolite2', IN_GEOLITE2_FAILED_TO_READ_DATABASE);
    }

    if (this.outdated) {
      await this.update();
    }
  }

  private async update(): Promise<void> {
    let reader: Reader<CountryResponse> | undefined;

    try {
      const response = await this.get(MAXMIND_GEO_LITE_2_COUNTRY_DATABASE_URL);

      const data = await buffer(response);

      reader = new Reader<CountryResponse>(data);

      await writeFile(this.path, data);

      this.updatedAt = Date.now();

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

  private async get(
    url: string,
    redirectionsLeft = 3,
  ): Promise<HTTP.IncomingMessage> {
    const urlObject = new URL(url);

    const {hostname} = urlObject;

    const port = getURLPort(urlObject);

    const [response] = (await once(
      HTTPS.get(url, {
        host: hostname,
        port, // Port is required here, otherwise it seems to be 80.
        createConnection: ((
          _args: object,
          callback: {
            (error: null, socket: Duplex): void;
            (error: Error): void;
          },
        ) => {
          this.tunnelServer
            .connect({type: 'in'}, undefined, hostname, port)
            .then(
              socket =>
                callback(
                  null,
                  TLS.connect({
                    socket,
                    servername: hostname,
                  }),
                ),
              error => callback(error),
            );
        }) as unknown as NonNullable<
          HTTP.ClientRequestArgs['createConnection']
        >,
      }),
      'response',
    )) as [HTTP.IncomingMessage];

    const {location} = response.headers;

    if (location !== undefined) {
      if (redirectionsLeft === 0) {
        throw new Error('Too many redirections.');
      }

      return this.get(location, redirectionsLeft - 1);
    }

    return response;
  }
}
