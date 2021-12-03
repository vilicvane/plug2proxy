import * as HTTP from 'http';
import * as HTTP2 from 'http2';
import * as Net from 'net';
import * as OS from 'os';
import {URL} from 'url';

import {
  HOP_BY_HOP_HEADERS_REGEX,
  destroyOnDrain,
  writeHTTPHead,
} from '../@common';
import {groupRawHeaders, refEventEmitter} from '../@utils';
import {InRoute} from '../types';

import {Server} from './server';

const HOSTNAME = OS.hostname();

const {
  name: PACKAGE_NAME,
  version: PACKAGE_VERSION,
  // eslint-disable-next-line @typescript-eslint/no-require-imports,@typescript-eslint/no-var-requires
} = require('../../../package.json');

const VIA = `1.1 ${HOSTNAME} (${PACKAGE_NAME}/${PACKAGE_VERSION})`;

const ROUTE_CACHE_EXPIRATION = 10 * 60_000;

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

    httpServer.listen(listenOptions, () => {
      let address = httpServer.address();

      if (typeof address !== 'string') {
        address = `${address?.address}:${address?.port}`;
      }

      console.info('proxy address:', address);
    });

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

    inSocket
      .on('end', () => {
        console.debug('in socket "end":', url);
      })
      .on('close', () => {
        console.debug('in socket "close":', url);
      })
      .on('error', error => {
        console.error('in socket error:', url, error.message);
      });

    let url = request.url!;

    let [host, portString] = url.split(':');

    let port = Number(portString) || 443;

    console.info(`connect ${host}:${port}.`);

    if (this.getCachedRoute(host) === 'direct') {
      this.directConnect(host, port, inSocket);
      return;
    }

    let sessionStream = await server.getSessionStream();

    if (inSocket.destroyed) {
      console.info('in socket closed before session stream acquired.');
      return;
    }

    let id = Proxy.getNextId();

    let connectEventSession = refEventEmitter(server.http2SecureServer).on(
      'stream',
      (
        outConnectStream: HTTP2.ServerHttp2Stream,
        headers: HTTP2.IncomingHttpHeaders,
      ) => {
        if (headers.id !== id) {
          if (server.http2SecureServer.listenerCount('stream') === 1) {
            console.error(
              'received unexpected request:',
              headers.type,
              headers.id,
            );
          }

          return;
        }

        connectEventSession.end();

        if (inSocket.destroyed) {
          outConnectStream.close();
          return;
        }

        outConnectStream.respond({});

        if (headers.type === 'connect-direct') {
          console.info(`routed ${host} to direct.`);

          this.setCachedRoute(host, 'direct');
          this.directConnect(host, port, inSocket);

          outConnectStream.end();
          return;
        }

        if (headers.type !== 'connect-ok') {
          console.error('unexpected request type:', headers.type);

          writeHTTPHead(inSocket, 500, 'Internal Server Error', true);

          outConnectStream.close();
          return;
        }

        console.info(`connected ${host}:${port}.`);

        writeHTTPHead(inSocket, 200, 'OK');

        inSocket.pipe(outConnectStream);
        outConnectStream.pipe(inSocket);

        // Debugging messages has already been added at the beginning of
        // `connect()`.
        inSocket.on('close', () => {
          outConnectStream.close();
        });

        outConnectStream
          .on('end', () => {
            console.debug('out stream "end".');
          })
          .on('close', () => {
            console.debug('out stream "close".');
            destroyOnDrain(inSocket);
          })
          .on('error', error => {
            console.error('out stream error:', error.message);
          });
      },
    );

    sessionStream.pushStream(
      {type: 'connect', id, host, port},
      (error, pushStream) => {
        if (error) {
          console.error('connect error:', error.message);

          writeHTTPHead(inSocket, 500, 'Internal Server Error', true);

          connectEventSession.end();
          return;
        }

        pushStream.respond({});

        if (inSocket.destroyed) {
          console.error('in socket destroyed while creating push stream.');
          pushStream.close();
        } else {
          inSocket.on('close', () => {
            pushStream.close();
          });
        }
      },
    );
  }

  private directConnect(
    host: string,
    port: number,
    inSocket: Net.Socket,
  ): void {
    console.info(`direct connect ${host}:${port}.`);

    let responded = false;

    let outSocket = Net.createConnection({host, port});

    inSocket.pipe(outSocket);
    outSocket.pipe(inSocket);

    // Debugging messages has already been added at the beginning of
    // `connect()`.
    inSocket.on('close', () => {
      outSocket.destroy();
    });

    outSocket
      .on('connect', () => {
        writeHTTPHead(inSocket, 200, 'OK');
        responded = true;
      })
      .on('end', () => {
        console.debug('out socket "end".');
      })
      .on('close', () => {
        console.debug('out socket "close".');
        destroyOnDrain(inSocket);

        // Close means it has been connected, thus must has been responded.
      })
      .on('error', error => {
        console.error('direct out socket error:', error.message);

        if (responded) {
          return;
        }

        responded = true;

        if (error && (error as any).code === 'ENOTFOUND') {
          writeHTTPHead(inSocket, 404, 'Not Found', true);
        } else {
          writeHTTPHead(inSocket, 502, 'Bad Gateway', true);
        }
      });
  }

  private async request(
    request: HTTP.IncomingMessage,
    response: HTTP.ServerResponse,
  ): Promise<void> {
    const server = this.server;

    let method = request.method!;
    let url = request.url!;

    console.info('request:', method, url);

    let inSocket = request.socket;

    request.socket.on('close', () => {
      console.debug('request/response socket "close".');
    });

    request
      .on('end', () => {
        console.debug('request "end".');
      })
      .on('error', error => {
        console.error('request error:', error.message);
      });

    response.on('error', error => {
      console.error('response error:', error.message);
    });

    let remoteAddress = request.socket.remoteAddress!;

    let parsedURL = new URL(url);

    if (parsedURL.protocol !== 'http:') {
      console.error('unsupported protocol:', url);

      // only "http://" is supported, "https://" should use CONNECT method
      response.writeHead(400).end();
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

    let host = new URL(url).hostname;

    let route = this.getCachedRoute(host);

    console.info(`route cached ${host}:`, route ?? '(none)');

    if (route === 'direct') {
      this.directRequest(method, url, headers, request, response);
      return;
    }

    let sessionStream = await server.getSessionStream();

    if (inSocket.destroyed) {
      console.info(
        'request/response socket destroyed while getting session stream:',
        method,
        url,
      );
      return;
    }

    let id = Proxy.getNextId();

    if (!route) {
      let routeEventSession = refEventEmitter<InRoute, HTTP2.Http2SecureServer>(
        server.http2SecureServer,
      ).on(
        'stream',
        (
          outStream: HTTP2.ServerHttp2Stream,
          headers: HTTP2.IncomingHttpHeaders,
        ) => {
          if (headers.id !== id) {
            if (server.http2SecureServer.listenerCount('stream') === 1) {
              console.error(
                'received unexpected request:',
                headers.type,
                headers.id,
              );
            }

            return;
          }

          outStream.respond({}, {endStream: true});

          if (headers.type !== 'route-result') {
            console.error('unexpected request type:', headers.type);
            response.writeHead(500).end();
            routeEventSession.end();
            return;
          }

          routeEventSession.end(headers.route as InRoute);
        },
      );

      sessionStream.pushStream(
        {
          id,
          type: 'route',
          host,
        },
        (error, pushStream) => {
          if (error) {
            console.warn('route error:', error.message);
            routeEventSession.end();
            return;
          }

          pushStream.respond({}, {endStream: true});
        },
      );

      route = (await routeEventSession.endedPromise)!;

      if (inSocket.destroyed) {
        console.debug('request/response socket destroyed while getting route.');
        return;
      }
    }

    if (route) {
      console.info(`route routed ${host}:`, route ?? '(none)');
      this.setCachedRoute(host, route);
    }

    if (route !== 'proxy') {
      this.directRequest(method, url, headers, request, response);
      return;
    }

    console.info('request via proxy:', method, url);

    let outRequestStream: HTTP2.ServerHttp2Stream | undefined;
    let outResponseStream: HTTP2.ServerHttp2Stream | undefined;

    let pushEventSession = refEventEmitter(server.http2SecureServer).on(
      'stream',
      (
        outStream: HTTP2.ServerHttp2Stream,
        outHeaders: HTTP2.IncomingHttpHeaders,
      ) => {
        if (outHeaders.id !== id) {
          if (server.http2SecureServer.listenerCount('stream') === 1) {
            console.error(
              'received unexpected request:',
              headers.type,
              headers.id,
            );
          }

          return;
        }

        pushEventSession.end();

        if (outHeaders.type !== 'response-stream') {
          console.error('unexpected request type:', headers.type);
          response.writeHead(500).end();
          outStream.close();
          return;
        }

        outResponseStream = outStream;

        // We only use this stream as Readable.
        outResponseStream.respond({}, {endStream: true});

        console.debug('received response:', url);

        response.writeHead(
          Number(outHeaders.status),
          JSON.parse(outHeaders.headers as string),
        );

        outResponseStream.pipe(response);

        outResponseStream
          .on('end', () => {
            console.debug('out response stream "end".');
          })
          .on('close', () => {
            console.debug('out response stream "close".');
            destroyOnDrain(response);
          })
          .on('error', error => {
            console.error('out response stream error:', error.message);
          });

        // Debugging messages added at the beginning of `request()`.
        response.on('close', () => {
          outResponseStream!.close();
        });
      },
    );

    sessionStream.pushStream(
      {type: 'request', id, method, url, headers: JSON.stringify(headers)},
      (error, pushStream) => {
        if (error) {
          pushEventSession.end();
          response.writeHead(500).end();
          return;
        }

        outRequestStream = pushStream;

        outRequestStream.respond();

        request.pipe(outRequestStream);

        outRequestStream
          .on('close', () => {
            console.debug('out request stream "close".');
            request!.destroy();
          })
          .on('error', error => {
            console.error('out request stream error:', error.message);
          });
      },
    );

    // Debugging messages added at the beginning of `request()`.
    request.on('close', () => {
      outRequestStream?.close();
    });
  }

  private directRequest(
    method: string,
    url: string,
    headers: HTTP.OutgoingHttpHeaders,
    request: HTTP.IncomingMessage,
    response: HTTP.ServerResponse,
  ): void {
    console.info('direct request:', method, url);

    let proxyRequest = HTTP.request(url, {method, headers}, proxyResponse => {
      let status = proxyResponse.statusCode!;

      console.info(`direct request response ${status}:`, method, url);

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

      proxyResponse
        .on('end', () => {
          console.debug('proxy response "end".');
        })
        .on('close', () => {
          console.debug('proxy response "close".');
          destroyOnDrain(response);
        })
        .on('error', error => {
          console.error('proxy response error:', error.message);
        });

      // Debugging messages added at the beginning of `request()`.
      response.on('close', () => {
        proxyResponse.destroy();
      });
    });

    request.pipe(proxyRequest);

    // Debugging messages added at the beginning of `request()`.
    request.on('error', () => {
      proxyRequest.destroy();
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

  static lastId = 0;

  static getNextId(): string {
    return (++this.lastId).toString();
  }
}
