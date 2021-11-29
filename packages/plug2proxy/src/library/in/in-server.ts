import * as HTTP from 'http';
import * as Net from 'net';
import * as TLS from 'tls';
import {URL} from 'url';

import {StreamJet} from 'socket-jet';

import {
  HOP_BY_HOP_HEADERS_REGEX,
  pipeBufferStreamToJet,
  pipeJetToBufferStream,
} from '../@common';
import {groupRawHeaders} from '../@utils';
import {debug, debugConnect, debugRequest} from '../debug';
import {
  InOutConnectOptions,
  InOutData,
  InOutRequestOptions,
  InRoute,
  OutInData,
  OutInResponseData,
} from '../types';

const DIRECT_CACHE_EXPIRATION = 10 * 60_000;

export interface InServerOptions {
  password?: string;
  tls: TLS.TlsOptions;
  listen: Net.ListenOptions;
}

export class InServer {
  readonly server: Net.Server;

  private cachedRouteMap = new Map<
    string,
    [route: InRoute, expiresAt: number]
  >();

  private jetResolvers: ((connection: InOutJet) => void)[] = [];

  private jets: InOutJet[] = [];

  constructor(readonly options: InServerOptions) {
    let server = TLS.createServer(options.tls, socket => {
      debug('out-in connection from %s established', socket.remoteAddress);

      let authorized = false;

      let jet = new StreamJet<OutInData, InOutData, Net.Socket>(socket, {
        heartbeat: true,
      });

      jet.on('error', error => {
        debug(
          'out-in connection from %s error %s',
          socket.remoteAddress,
          (error as any).code ?? error.message,
        );
      });

      jet.on('data', data => {
        switch (data.type) {
          case 'initialize':
            if (!authorized) {
              if (options.password === data.password) {
                debug(
                  'out-in connection from %s authorized',
                  socket.remoteAddress,
                );
                authorized = true;
              } else {
                debug(
                  'out-in connection from %s denied %s',
                  socket.remoteAddress,
                );

                jet.write({type: 'error', message: 'Permission denied'});
                jet.end();
              }
            }

            this.resolveJet(jet);
            break;
        }
      });

      socket.on('close', () => {
        debug('out-in connection from %s closed', socket.remoteAddress);
      });
    });

    server.listen(options.listen);

    this.server = server;
  }

  async connect(
    options: InOutConnectOptions,
    inSocket: Net.Socket,
  ): Promise<void> {
    let {host, port} = options;

    if (this.getCachedRoute(host) === 'direct') {
      return this.directConnect(options, inSocket);
    }

    let jet = await this.retrieveJet();

    debugConnect('connecting %s:%d via tunnel', host, port);

    jet.write({
      type: 'connect',
      options,
    });

    let connected: boolean;

    let cleanUpJet: (() => void) | undefined;

    try {
      connected = await new Promise<boolean>((resolve, reject) => {
        let onData = (data: OutInData): void => {
          switch (data.type) {
            case 'connected':
              resolve(true);
              break;
            case 'direct':
              resolve(false);
              break;
            default:
              reject(new Error(`Unexpected Jet data "${data.type}"`));
          }
        };

        jet.once('data', onData);
        jet.once('error', reject);

        cleanUpJet = () => {
          jet.off('data', onData);
          jet.off('error', reject);
        };
      });
      cleanUpJet?.();

      inSocket.write('HTTP/1.1 200 Connection established\r\n\r\n');
    } catch (error) {
      cleanUpJet?.();

      debugConnect('connect error %s:%d', host, port);

      inSocket.end('HTTP/1.1 500 Internal Server Error\r\n\r\n');

      return;
    }

    this.setCachedRoute(host, connected ? 'proxy' : 'direct');

    if (!connected) {
      debugConnect('tunnel asks %s:%d for direct connect', host, port);

      return this.directConnect(options, inSocket);
    }

    debugConnect('connected %s:%d via tunnel', host, port);

    pipeJetToBufferStream(jet, inSocket);

    pipeBufferStreamToJet(inSocket, jet);

    inSocket.on('end', () => {
      debugConnect('connect ended %s:%d', host, port);

      jet.write({
        type: 'stream-end',
      });
    });

    inSocket.on('error', () => {
      debugConnect('connect error %s:%d', host, port);

      jet.write({
        type: 'stream-end',
      });
    });
  }

  async request(
    options: InOutRequestOptions,
    request: HTTP.IncomingMessage,
    response: HTTP.ServerResponse,
  ): Promise<void> {
    let host = new URL(options.url).hostname;

    let route = this.getCachedRoute(host);

    debugRequest('route cache %s %s', route ?? '(none)', host);

    if (route === 'direct') {
      this.directRequest(options, request, response);
      return;
    }

    if (!route) {
      let routeJet = await this.retrieveJet();

      routeJet.write({
        type: 'route',
        host,
      });

      route = await new Promise<InRoute>((resolve, reject) => {
        routeJet.once('data', data => {
          switch (data.type) {
            case 'route-result':
              resolve(data.route);
              break;
            default:
              reject(new Error(`Unexpected Jet data "${data.type}"`));
          }
        });
      });

      if (route) {
        debugRequest('routed %s %s', route, host);

        this.setCachedRoute(host, route);

        if (route === 'direct') {
          this.directRequest(options, request, response);
          return;
        }
      }
    }

    let jet = await this.retrieveJet();

    debugRequest('requesting %s %s via proxy', options.method, options.url);

    jet.write({
      type: 'request',
      options,
    });

    pipeBufferStreamToJet(request, jet);

    let {status, headers} = await new Promise<OutInResponseData>(
      (resolve, reject) => {
        jet.once('data', data => {
          switch (data.type) {
            case 'response':
              resolve(data);
              break;
            default:
              reject(new Error(`Unexpected Jet data "${data.type}"`));
          }
        });
      },
    );

    response.writeHead(status, headers);

    pipeJetToBufferStream(jet, response);
  }

  private directConnect(
    options: InOutConnectOptions,
    inSocket: Net.Socket,
  ): void {
    let {host, port} = options;

    debugConnect('direct connect %s:%d', host, port);

    let responded = false;

    let outSocket = Net.createConnection(options, () => {
      inSocket.write('HTTP/1.1 200 Connection established\r\n\r\n');

      responded = true;

      outSocket.on('end', () => {
        debugConnect('out socket to %s:%d ended', host, port);
      });
    });

    outSocket.on('error', (error: any) => {
      debugConnect(
        'out socket to %s:%d error %s',
        host,
        port,
        error.code ?? error.message,
      );

      if (responded) {
        return;
      }

      if (error.code === 'ENOTFOUND') {
        inSocket.end('HTTP/1.1 404 Not Found\r\n\r\n');
      } else {
        inSocket.end('HTTP/1.1 500 Internal Server Error\r\n\r\n');
      }
    });

    inSocket.pipe(outSocket);
    outSocket.pipe(inSocket);
  }

  private directRequest(
    {url, ...options}: InOutRequestOptions,
    request: HTTP.IncomingMessage,
    response: HTTP.ServerResponse,
  ): void {
    let {method} = options;

    debugRequest('direct request %s %s', method, url);

    let proxyRequest = HTTP.request(url, options, proxyResponse => {
      let status = proxyResponse.statusCode!;

      debugRequest('direct request response %s %s %d', method, url, status);

      let headers: {[key: string]: string | string[]} = {};

      for (let [key, value] of groupRawHeaders(proxyResponse.rawHeaders)) {
        if (HOP_BY_HOP_HEADERS_REGEX.test(key)) {
          continue;
        }

        let existingValue = headers[key];

        if (Array.isArray(existingValue)) {
          existingValue.push(value);
        } else if (existingValue !== undefined) {
          headers[key] = [existingValue, value];
        } else {
          headers[key] = value;
        }
      }

      response.writeHead(status, headers);

      proxyResponse.pipe(response);

      proxyResponse.on('error', error => {
        debugRequest(
          'direct request response error %s',
          (error as any).code ?? error.message,
        );
      });
    });

    request.pipe(proxyRequest);

    request.on('close', () => {
      debugRequest('direct request closed %s', url);
    });
  }

  private resolveJet(jet: InOutJet): void {
    let resolver = this.jetResolvers.shift();

    if (resolver) {
      resolver(jet);
    } else {
      this.jets.push(jet);
    }
  }

  private async retrieveJet(): Promise<InOutJet> {
    let jet = this.jets.shift();

    if (!jet) {
      jet = await new Promise<InOutJet>(resolve => {
        this.jetResolvers.push(resolve);
      });
    }

    return jet;
  }

  private getCachedRoute(host: string): InRoute | undefined {
    let now = Date.now();

    let cache = this.cachedRouteMap.get(host);

    if (!cache) {
      return undefined;
    }

    let [route, expiresAt] = cache;

    return typeof expiresAt === 'number' && expiresAt > now ? route : undefined;
  }

  private setCachedRoute(host: string, route: InRoute): void {
    this.cachedRouteMap.set(host, [
      route,
      Date.now() + DIRECT_CACHE_EXPIRATION,
    ]);
  }
}

export type InOutJet = StreamJet<OutInData, InOutData, Net.Socket>;
