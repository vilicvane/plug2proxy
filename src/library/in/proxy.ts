import * as HTTP from 'http';
import type * as HTTP2 from 'http2';
import * as Net from 'net';
import * as OS from 'os';
import {URL} from 'url';

import {
  HOP_BY_HOP_HEADERS_REGEX,
  destroyOnDrain,
  writeHTTPHead,
} from '../@common';
import {groupRawHeaders, refEventEmitter} from '../@utils';
import type {InRoute} from '../types';

import type {Server} from './server';

const HOSTNAME = OS.hostname();

const {
  name: PACKAGE_NAME,
  version: PACKAGE_VERSION,
  // eslint-disable-next-line @typescript-eslint/no-require-imports,@typescript-eslint/no-var-requires
} = require('../../../package.json');

const VIA = `1.1 ${HOSTNAME} (${PACKAGE_NAME}/${PACKAGE_VERSION})`;

const ROUTE_CACHE_EXPIRATION = 10 * 60_000;
const SOCKET_TIMEOUT_AFTER_END = 60_000;

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

    let url = request.url!;

    let [host, portString] = url.split(':');

    let logPrefix = `[-][${host}]`;

    inSocket
      .on('end', () => {
        console.debug(`${logPrefix} in socket "end".`);
        inSocket.setTimeout(SOCKET_TIMEOUT_AFTER_END);
      })
      .on('close', () => {
        console.debug(`${logPrefix} in socket "close".`);
      })
      .on('timeout', () => {
        console.debug(`${logPrefix} in socket "timeout".`);
        inSocket.destroy();
      })
      .on('error', error => {
        console.error(`${logPrefix} in socket error:`, error.message);
      });

    let port = Number(portString) || 443;

    console.info(`${logPrefix} connect: ${host}:${port}`);

    if (this.getCachedRoute(host) === 'direct') {
      this.directConnect(host, port, inSocket, logPrefix);
      return;
    }

    let sessionCandidate = await server.getSessionCandidate(logPrefix);

    if (inSocket.destroyed) {
      console.info(
        `${logPrefix} in socket closed before session stream acquired.`,
      );
      return;
    }

    let id: string | undefined;

    let connectEventSession = refEventEmitter(server.http2SecureServer).on(
      'stream',
      (
        outConnectStream: HTTP2.ServerHttp2Stream,
        headers: HTTP2.IncomingHttpHeaders,
      ) => {
        if (headers.id !== id) {
          if (server.http2SecureServer.listenerCount('stream') === 1) {
            console.error(
              `${logPrefix} received unexpected request ${headers.id} (${headers.type}).`,
            );
          }

          return;
        }

        connectEventSession.end();

        if (inSocket.destroyed) {
          outConnectStream.destroy();
          return;
        }

        outConnectStream.respond();

        if (headers.type === 'connect-direct') {
          console.info(`${logPrefix} routed to direct.`);

          this.setCachedRoute(host, 'direct');
          this.directConnect(host, port, inSocket, logPrefix);

          outConnectStream.end();
          return;
        }

        if (headers.type !== 'connect-ok') {
          console.error(
            `${logPrefix} unexpected request type ${headers.type}.`,
          );

          writeHTTPHead(inSocket, 500, 'Internal Server Error', true);

          outConnectStream.destroy();
          return;
        }

        console.info(`${logPrefix} connected.`);

        writeHTTPHead(inSocket, 200, 'OK');

        inSocket.pipe(outConnectStream);
        outConnectStream.pipe(inSocket);

        // Debugging messages has already been added at the beginning of
        // `connect()`.
        inSocket.on('close', () => {
          outConnectStream.destroy();
        });

        outConnectStream
          .on('end', () => {
            console.debug(`${logPrefix} out stream "end".`);
          })
          .on('close', () => {
            console.debug(`${logPrefix} out stream "close".`);
            destroyOnDrain(inSocket);
          })
          .on('error', error => {
            console.error(`${logPrefix} out stream error:`, error.message);
          });
      },
    );

    sessionCandidate.stream.pushStream(
      {type: 'connect', host, port},
      (error, pushStream) => {
        if (error) {
          console.error(`${logPrefix} connect error:`, error.message);

          writeHTTPHead(inSocket, 500, 'Internal Server Error', true);

          connectEventSession.end();
          return;
        }

        id = `${sessionCandidate.id}:${pushStream.id}`;
        logPrefix = `[${id}][${host}]`;

        pushStream
          .on('close', () => {
            console.debug(`${logPrefix} connect push stream "close".`);
          })
          .on('error', error => {
            console.debug(
              `${logPrefix} connect push stream error:`,
              error.message,
            );
          });

        if (inSocket.destroyed) {
          console.error(
            `${logPrefix} in socket destroyed while creating push stream.`,
          );
          pushStream.destroy();
        } else {
          pushStream.respond();

          inSocket.on('close', () => {
            pushStream.destroy();
          });
        }
      },
    );
  }

  private directConnect(
    host: string,
    port: number,
    inSocket: Net.Socket,
    logPrefix: string,
  ): void {
    console.info(`${logPrefix} direct connect.`);

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
        console.debug(`${logPrefix} out socket "end".`);
      })
      .on('close', () => {
        console.debug(`${logPrefix} out socket "close".`);
        destroyOnDrain(inSocket);

        // Close means it has been connected, thus must has been responded.
      })
      .on('error', error => {
        console.error(`${logPrefix} direct out socket error:`, error.message);

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
    let parsedURL = new URL(url);
    let host = parsedURL.hostname;

    let logPrefix = `[-][${host}]`;

    console.info(`${logPrefix} request:`, method, url);

    let inSocket = request.socket;

    request.socket.on('close', () => {
      console.debug(`${logPrefix} request/response socket "close".`);
    });

    request
      .on('end', () => {
        console.debug(`${logPrefix} request "end".`);
      })
      .on('error', error => {
        console.error(`${logPrefix} request error:`, error.message);
      });

    response.on('error', error => {
      console.error(`${logPrefix} response error:`, error.message);
    });

    let remoteAddress = request.socket.remoteAddress!;

    if (parsedURL.protocol !== 'http:') {
      console.error(`${logPrefix} unsupported protocol:`, url);

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

    let route = this.getCachedRoute(host);

    console.info(`${logPrefix} route cached ${route ?? '(none)'}.`);

    if (route === 'direct') {
      this.directRequest(method, url, headers, request, response, logPrefix);
      return;
    }

    let sessionCandidate = await server.getSessionCandidate(logPrefix);

    if (inSocket.destroyed) {
      console.info(
        `${logPrefix} request/response socket destroyed while getting session stream.`,
      );
      return;
    }

    let id: string | undefined;

    let pushEventSession = refEventEmitter(server.http2SecureServer).on(
      'stream',
      (
        outStream: HTTP2.ServerHttp2Stream,
        outHeaders: HTTP2.IncomingHttpHeaders,
      ) => {
        if (outHeaders.id !== id) {
          if (server.http2SecureServer.listenerCount('stream') === 1) {
            console.error(
              `${logPrefix} received unexpected request ${headers.id} (${headers.type}).`,
            );
          }

          return;
        }

        if (request.socket.destroyed) {
          pushEventSession.end();
          outStream.destroy();
          return;
        }

        outStream.respond();

        if (outHeaders.type === 'request-direct') {
          pushEventSession.end();

          console.info(`${logPrefix} routed to direct.`);

          this.setCachedRoute(host, 'direct');
          this.directRequest(
            method,
            url,
            headers,
            request,
            response,
            logPrefix,
          );

          outStream.end();
          return;
        }

        if (
          // This happens after 'request-response'.
          outHeaders.type === 'response-headers' ||
          outHeaders.type === 'response-headers-end'
        ) {
          pushEventSession.end();

          console.info(`${logPrefix} received response headers.`);

          response.writeHead(
            Number(outHeaders.status),
            outHeaders.headers && JSON.parse(outHeaders.headers as string),
          );

          outStream.end();

          if (outHeaders.type === 'response-headers-end') {
            response.end();
          }

          return;
        }

        if (outHeaders.type !== 'request-response') {
          pushEventSession.end();

          console.error(
            `${logPrefix} unexpected request type ${headers.type}.`,
          );
          response.writeHead(500).end();
          outStream.destroy();
          return;
        }

        console.debug(`${logPrefix} request-response stream received.`);

        request.pipe(outStream);
        outStream.pipe(response);

        outStream
          .on('end', () => {
            console.debug(`${logPrefix} out response stream "end".`);
          })
          .on('close', () => {
            console.debug(`${logPrefix} out response stream "close".`);
            destroyOnDrain(response);
          })
          .on('error', error => {
            console.error(
              `${logPrefix} out response stream error:`,
              error.message,
            );
          });

        // Debugging messages added at the beginning of `request()`.
        response.on('close', () => {
          outStream!.destroy();
        });
      },
    );

    sessionCandidate.stream.pushStream(
      {type: 'request', method, url, headers: JSON.stringify(headers)},
      (error, pushStream) => {
        if (error) {
          pushEventSession.end();
          response.writeHead(500).end();
          return;
        }

        id = `${sessionCandidate.id}:${pushStream.id}`;
        logPrefix = `[${id}][${host}]`;

        pushStream
          .on('close', () => {
            console.debug(`${logPrefix} out request stream "close".`);
          })
          .on('error', error => {
            console.error(
              `${logPrefix} out request stream error:`,
              error.message,
            );
          });

        if (request.socket.destroyed) {
          console.error(
            `${logPrefix} request socket destroyed while creating push stream.`,
          );
          pushStream.destroy();
        } else {
          pushStream.respond();

          // Debugging messages added at the beginning of `request()`.
          request.socket.on('close', () => {
            pushStream.destroy();
          });
        }
      },
    );
  }

  private directRequest(
    method: string,
    url: string,
    headers: HTTP.OutgoingHttpHeaders,
    request: HTTP.IncomingMessage,
    response: HTTP.ServerResponse,
    logPrefix: string,
  ): void {
    console.info(`${logPrefix} direct request.`);

    let proxyRequest = HTTP.request(url, {method, headers}, proxyResponse => {
      let status = proxyResponse.statusCode!;

      console.info(`${logPrefix} direct request response ${status}.`);

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
          console.debug(`${logPrefix} proxy response "end".`);
        })
        .on('close', () => {
          console.debug(`${logPrefix} proxy response "close".`);
          destroyOnDrain(response);
        })
        .on('error', error => {
          console.error(`${logPrefix} proxy response error:`, error.message);
        });

      // Debugging messages added at the beginning of `request()`.
      response.on('close', () => {
        proxyResponse.destroy();
      });
    }).on('error', error => {
      console.debug(`${logPrefix} proxy request error:`, error.message);
      destroyOnDrain(response);
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
}
