import * as HTTP from 'http';
import * as Net from 'net';
import * as OS from 'os';
import {URL} from 'url';

import Debug from 'debug';

import {
  HOP_BY_HOP_HEADERS_REGEX,
  pipeBufferStreamToJet,
  pipeJetToBufferStream,
  writeHTTPHead,
} from '../@common';
import {groupRawHeaders, refEventEmitter} from '../@utils';
import {
  InOutConnectOptions,
  InOutRequestOptions,
  OutInPacket,
  OutInRequestResponsePacket,
} from '../packets';
import {InRoute} from '../types';

import {Connection} from './connection';
import {Server} from './server';

const HOSTNAME = OS.hostname();

const {
  name: PACKAGE_NAME,
  version: PACKAGE_VERSION,
  // eslint-disable-next-line @typescript-eslint/no-require-imports,@typescript-eslint/no-var-requires
} = require('../../../package.json');

const VIA = `1.1 ${HOSTNAME} (${PACKAGE_NAME}/${PACKAGE_VERSION})`;

const ROUTE_CACHE_EXPIRATION = 10 * 60_000;

const debugConnect = Debug('p2p:in:proxy:connect');
const debugRequest = Debug('p2p:in:proxy:request');

export interface ProxyOptions {
  /**
   * 代理入口监听选项，如：
   *
   * ```json
   * {
   *   "host": "127.0.0.1",
   *   "port": 8000
   * }
   * ```
   */
  listen: Net.ListenOptions;
}

export class Proxy {
  readonly httpServer: HTTP.Server;

  private cachedRouteMap = new Map<
    string,
    [route: InRoute, expiresAt: number]
  >();

  constructor(readonly server: Server, {listen: listenOptions}: ProxyOptions) {
    let httpServer = new HTTP.Server();

    httpServer.on('connect', this.onHTTPServerConnect);
    httpServer.on('request', this.onHTTPServerRequest);

    httpServer.listen(listenOptions);

    this.httpServer = httpServer;
  }

  private onHTTPServerConnect = (
    request: HTTP.IncomingMessage,
    socket: Net.Socket,
  ): void => {
    void this.connect(request, socket);
  };

  private onHTTPServerRequest = (
    request: HTTP.IncomingMessage,
    response: HTTP.ServerResponse,
  ): void => {
    void this.request(request, response);
  };

  private async connect(
    request: HTTP.IncomingMessage,
    inSocket: Net.Socket,
  ): Promise<void> {
    const server = this.server;

    let url = request.url!;

    inSocket.on('error', error => {
      debugConnect('in socket error %s %e', url, error);
    });

    let [host, portString] = url.split(':');

    let port = Number(portString) || 443;

    let options: InOutConnectOptions = {
      host,
      port,
    };

    debugConnect('connect %s:%d', host, port);

    if (this.getCachedRoute(host) === 'direct') {
      return this.directConnect(options, inSocket);
    }

    let connection: Connection;

    try {
      connection = await server.claimConnection([
        {
          type: 'connect',
          options,
        },
      ]);
    } catch (error) {
      debugConnect('failed to claim connection %e', error);

      if (inSocket.writable) {
        writeHTTPHead(inSocket, 503, 'Service Unavailable', true);
      }

      return;
    }

    connection.resume();

    if (inSocket.destroyed) {
      server.returnConnection(connection);
      return;
    }

    let eventSession = refEventEmitter(connection);

    try {
      let route = await new Promise<InRoute>((resolve, reject) => {
        eventSession
          .on('data', (packet: OutInPacket) => {
            switch (packet.type) {
              case 'connection-established':
                connection.pause();
                resolve('proxy');
                break;
              case 'connection-direct':
                connection.pause();
                resolve('direct');
                break;
              case 'connection-error':
                reject();
                break;
              case 'pong':
                break;
              default:
                reject(
                  new Error(
                    `Unexpected out-in packet, expecting "connection-established"/"connection-direct"/"connection-error", received ${JSON.stringify(
                      packet.type,
                    )}`,
                  ),
                );
                break;
            }
          })
          .on('close', () =>
            reject(new Error('Connection closed before establish')),
          )
          .on('error', reject);
      });

      connection.resume();

      this.setCachedRoute(host, route);

      if (route === 'direct') {
        server.returnConnection(connection);
        this.directConnect(options, inSocket);
        return;
      }
    } catch (error) {
      if (error) {
        writeHTTPHead(inSocket, 500, 'Internal Server Error', true);
        server.dropConnection(connection);
      } else {
        // Return connection on "connection-error".
        writeHTTPHead(inSocket, 502, 'Bad Gateway', true);
        server.returnConnection(connection);
      }

      return;
    } finally {
      eventSession.end();
    }

    if (inSocket.destroyed) {
      server.returnConnection(connection);
      return;
    }

    writeHTTPHead(inSocket, 200, 'OK');

    pipeBufferStreamToJet(inSocket, connection);
    pipeJetToBufferStream(connection, inSocket);

    inSocket
      .on('close', () => {
        connection.debug('in socket closed %s', url);
        server.returnConnection(connection);
      })
      .on('error', () => {
        connection.debug('in socket error %s', url);
      });
  }

  private directConnect(
    options: InOutConnectOptions,
    inSocket: Net.Socket,
  ): void {
    if (!inSocket.writable) {
      return;
    }

    let {host, port} = options;

    debugConnect('direct connect %s:%d', host, port);

    let responded = false;

    let outSocket = Net.createConnection(options);

    outSocket
      .on('connect', () => {
        writeHTTPHead(inSocket, 200, 'OK');

        responded = true;

        outSocket.on('end', () => {
          debugConnect('out socket to %s:%d ended', host, port);
        });
      })
      .on('error', (error: any) => {
        debugConnect('out socket to %s:%d error %e', host, port, error);

        if (responded) {
          return;
        }

        if (error.code === 'ENOTFOUND') {
          writeHTTPHead(inSocket, 404, 'Not Found', true);
        } else {
          writeHTTPHead(inSocket, 502, 'Bad Gateway', true);
        }
      });

    inSocket.pipe(outSocket);
    outSocket.pipe(inSocket);
  }

  private async request(
    request: HTTP.IncomingMessage,
    response: HTTP.ServerResponse,
  ): Promise<void> {
    const server = this.server;

    // proxy the request HTTP method
    let method = request.method!;
    let url = request.url!;

    debugRequest('request %s %s', method, url);

    let inSocket = request.socket;

    let remoteAddress = inSocket.remoteAddress!;

    let parsedURL = new URL(url);

    if (parsedURL.protocol !== 'http:') {
      debugRequest('unsupported protocol %s %s', method, url);

      // only "http://" is supported, "https://" should use CONNECT method
      response.writeHead(400);
      response.end();
      return;
    }

    // setup outbound proxy request HTTP headers
    let headers: {[key: string]: string | string[]} = {};

    let xForwardedForExists = false;
    let viaExists = false;

    for (let [key, value] of groupRawHeaders(request.rawHeaders)) {
      let keyLower = key.toLowerCase();

      // TODO: seems buggy to me.

      if (!xForwardedForExists && 'x-forwarded-for' === keyLower) {
        // append to existing "X-Forwarded-For" header
        // http://en.wikipedia.org/wiki/X-Forwarded-For
        xForwardedForExists = true;
        value += `, ${remoteAddress}`;
      }

      if (!viaExists && 'via' === keyLower) {
        // append to existing "Via" header
        viaExists = true;
        value += `, ${VIA}`;
      }

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

    // add "X-Forwarded-For" header if it's still not here by now
    // http://en.wikipedia.org/wiki/X-Forwarded-For
    if (!xForwardedForExists) {
      headers['X-Forwarded-For'] = remoteAddress;
    }

    // add "Via" header if still not set by now
    if (!viaExists) {
      headers.Via = VIA;
    }

    let options = {method, url, headers};

    let host = new URL(url).hostname;

    let route = this.getCachedRoute(host);

    debugRequest('route cache %s %s', route ?? '(none)', host);

    if (route === 'direct') {
      this.directRequest(options, request, response);
      return;
    }

    let connection: Connection;

    if (route) {
      try {
        connection = await server.claimConnection();
      } catch (error) {
        debugRequest('failed to claim connection %e', error);

        if (response.writable) {
          response.writeHead(503);
          response.end();
        }

        return;
      }

      connection.resume();
    } else {
      try {
        connection = await server.claimConnection([
          {
            type: 'route',
            host,
          },
        ]);
      } catch (error) {
        debugRequest('failed to claim connection %e', error);

        if (response.writable) {
          response.writeHead(503);
          response.end();
        }

        return;
      }

      connection.resume();

      if (request.destroyed) {
        server.returnConnection(connection);
        return;
      }

      connection.debug('wait for route result %s', host);

      let eventSession = refEventEmitter(connection);

      try {
        let route = await new Promise<InRoute>((resolve, reject) => {
          eventSession
            .on('data', (packet: OutInPacket) => {
              switch (packet.type) {
                case 'route-result':
                  connection.pause();
                  resolve(packet.route);
                  break;
                case 'pong':
                  break;
                default:
                  reject(
                    new Error(
                      `Unexpected out-in packet, expecting "route-result", received ${JSON.stringify(
                        packet.type,
                      )}`,
                    ),
                  );
                  break;
              }
            })
            .on('close', () =>
              reject(new Error('Connection closed before "route-result"')),
            )
            .on('error', reject);
        });

        connection.resume();

        connection.debug('routed %s %s', route, host);

        this.setCachedRoute(host, route);

        if (route === 'direct') {
          server.returnConnection(connection);
          this.directRequest(options, request, response);
          return;
        }
      } catch (error) {
        if (error) {
          response.writeHead(500);
          response.end();
          server.dropConnection(connection);
        } else {
          // Return connection on "connection-error".
          response.writeHead(502);
          response.end();
          server.returnConnection(connection);
        }

        return;
      } finally {
        eventSession.end();
      }
    }

    if (request.destroyed) {
      server.returnConnection(connection);
      return;
    }

    connection.debug('requesting %s %s via proxy', method, url);

    connection.write({
      type: 'request',
      options,
    });

    request.on('error', error => {
      connection.debug('request error %e', error);
    });

    request.on('end', () => {
      connection.debug('request ended');
    });

    pipeBufferStreamToJet(request, connection);

    let eventSession = refEventEmitter(connection);

    let responsePacket: OutInRequestResponsePacket;

    try {
      responsePacket = await new Promise((resolve, reject) => {
        eventSession
          .on('data', packet => {
            switch (packet.type) {
              case 'request-response':
                connection.pause();
                resolve(packet);
                break;
              case 'pong':
                break;
              default:
                reject(
                  new Error(
                    `Unexpected out-in packet, expecting "request-response", received ${JSON.stringify(
                      packet.type,
                    )}`,
                  ),
                );
                break;
            }
          })
          .on('close', () =>
            reject(new Error('Connection closed before response')),
          )
          .on('error', reject);
      });

      connection.resume();
    } catch (error) {
      connection.debug('response error %e', error);

      if (response.writable) {
        response.writeHead(500);
        response.end();
      }

      server.dropConnection(connection);

      return;
    } finally {
      eventSession.end();
    }

    if (response.destroyed) {
      server.returnConnection(connection);
      return;
    }

    response.writeHead(responsePacket.status, responsePacket.headers);

    pipeJetToBufferStream(connection, response);

    response.on('close', () => {
      connection.debug('response close');
      server.returnConnection(connection);
    });
  }

  private directRequest(
    {url, ...options}: InOutRequestOptions,
    request: HTTP.IncomingMessage,
    response: HTTP.ServerResponse,
  ): void {
    if (!response.writable) {
      return;
    }

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
        debugRequest('direct request response error %e', error);
      });
    });

    request.pipe(proxyRequest);

    request.on('close', () => {
      debugRequest('direct request closed %s', url);
    });
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
    this.cachedRouteMap.set(host, [route, Date.now() + ROUTE_CACHE_EXPIRATION]);
  }
}
