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
import type {TunnelServer} from '../tunnel-server.js';

import type {RuleMatch} from './rule-match.js';

const MAXMIND_GEO_LITE_2_COUNTRY_DATABASE_URL =
  'https://github.com/P3TERX/GeoLite.mmdb/releases/latest/download/GeoLite2-Country.mmdb';

const UPDATE_INTERVAL = ms('24h');

const UPDATE_RETRY_INTERVAL = ms('30s');

export type GeoLite2Options = {
  path: string;
};

export class GeoLite2 {
  readonly path: string;

  tunnelServer!: TunnelServer;

  private initializeCalled = false;

  private readerPromise: Promise<Reader<CountryResponse> | false>;

  private readerResolver:
    | ((reader: Reader<CountryResponse> | false) => void)
    | undefined;

  constructor({path}: GeoLite2Options) {
    this.path = path;

    this.readerPromise = new Promise(resolve => {
      this.readerResolver = resolve;
    });
  }

  createGeoIPRuleMatch(match: string | string[]): RuleMatch {
    const matches = Array.isArray(match) ? match : [match];

    const route = async (ips: string[]): Promise<boolean | undefined> => {
      await this.initialize();

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
    if (this.initializeCalled) {
      return;
    }

    this.initializeCalled = true;

    let updatedAt: number | undefined;

    try {
      const stats = await stat(this.path);

      updatedAt = stats.mtimeMs + UPDATE_INTERVAL;

      const data = await readFile(this.path);

      this.readerResolver!(new Reader(data));
      this.readerResolver = undefined;
    } catch (error) {
      Logs.warn('geolite2', IN_GEOLITE2_FAILED_TO_READ_DATABASE);
    }

    setTimeout(
      () => this.update(),
      updatedAt === undefined ? 0 : Math.max(updatedAt - Date.now(), 0),
    );
  }

  private updateTimer: NodeJS.Timeout | undefined;

  private async update(): Promise<void> {
    clearTimeout(this.updateTimer);

    let reader: Reader<CountryResponse> | undefined;

    try {
      const response = await this.get(MAXMIND_GEO_LITE_2_COUNTRY_DATABASE_URL);

      const data = await buffer(response);

      reader = new Reader<CountryResponse>(data);

      await writeFile(this.path, data);

      Logs.info('geolite2', IN_GEOLITE2_DATABASE_UPDATED);
    } catch (error) {
      Logs.error('geolite2', IN_GEOLITE2_DATABASE_UPDATE_FAILED);
      Logs.debug('geolite2', error);
    }

    this.updateTimer = setTimeout(
      () => void this.update(),
      reader ? UPDATE_INTERVAL : UPDATE_RETRY_INTERVAL,
    );

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
    const {protocol, host, port: portString} = new URL(url);

    const port = parseInt(portString) || (protocol === 'https:' ? 443 : 80);

    const [response] = (await once(
      HTTPS.get(url, {
        host,
        port, // Port is required here, otherwise it seems to be 80.
        createConnection: ((
          _args: object,
          callback: {
            (error: null, socket: Duplex): void;
            (error: Error): void;
          },
        ) => {
          this.tunnelServer.connect({type: 'in'}, undefined, host, port).then(
            socket =>
              callback(
                null,
                TLS.connect({
                  socket,
                  servername: host,
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
