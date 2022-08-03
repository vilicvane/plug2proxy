import * as HTTP from 'http';
import type * as HTTP2 from 'http2';
import * as Net from 'net';
import * as OS from 'os';
import {URL} from 'url';

import ms from 'ms';
import * as x from 'x-value';

import {
  HOP_BY_HOP_HEADERS_REGEX,
  destroyOnDrain,
  writeHTTPHead,
} from '../@common';
import {groupRawHeaders, probeDestinationIP} from '../@utils';
import {IPPattern, Port} from '../@x-types';
import type {InRoute} from '../types';

import type {Server, ServerStreamListener} from './server';

const HOSTNAME = OS.hostname();

const {
  name: PACKAGE_NAME,
  version: PACKAGE_VERSION,
  // eslint-disable-next-line @typescript-eslint/no-require-imports,@typescript-eslint/no-var-requires
} = require('../../../package.json');

const VIA = `1.1 ${HOSTNAME} (${PACKAGE_NAME}/${PACKAGE_VERSION})`;

const ROUTE_CACHE_EXPIRATION = ms('10m');
const SOCKET_TIMEOUT_AFTER_END = ms('1m');

const LISTEN_HOST_DEFAULT = IPPattern.nominalize('127.0.0.1');
const LISTEN_PORT_DEFAULT = Port.nominalize(8000);

const IP_PROBE_ENABLED_DEFAULT = true;
const IP_PROBE_TIMEOUT_DEFAULT = 250;

export const ProxyOptions = x.object({
  host: IPPattern.optional(),
  port: Port.optional(),
  /**
   * 目前 Plug2Proxy 主要的路由功能是通过出口端完成的，客户端仅支持少量配置。
   */
  routing: x
    .object({
      /**
       * 提前从客户端探测 IP 地址，供出口端路由参考。
       */
      ipProbe: x
        .union(
          x.boolean,
          x.object({
            timeout: x.number.optional(),
          }),
        )
        .optional(),
    })
    .optional(),
});

export type ProxyOptions = x.TypeOf<typeof ProxyOptions>;

export class Proxy {
  readonly httpServer: HTTP.Server;

  private cachedRouteMap = new Map<
    string,
    [route: InRoute, expiresAt: number]
  >();

  private ipProbeEnabled: boolean;
  private ipProbeTimeout: number;

  private probingPromiseMap = new Map<string, Promise<string | undefined>>();

  constructor(
    readonly server: Server,
    {
      host = LISTEN_HOST_DEFAULT,
      port = LISTEN_PORT_DEFAULT,
      routing: {ipProbe = IP_PROBE_ENABLED_DEFAULT} = {},
    }: ProxyOptions,
  ) {
    let httpServer = new HTTP.Server();

    httpServer.on('connect', this.onHTTPServerConnect);
    httpServer.on('request', this.onHTTPServerRequest);

    httpServer.listen(
      {
        host,
        port,
      },
      () => {
        let address = httpServer.address();

        if (typeof address !== 'string') {
          address = `${address?.address}:${address?.port}`;
        }

        console.info(`[proxy] listening on ${address}...`);
      },
    );

    this.httpServer = httpServer;

    if (ipProbe !== false) {
      let {timeout = IP_PROBE_TIMEOUT_DEFAULT} =
        ipProbe === true ? {} : ipProbe;

      this.ipProbeEnabled = true;
      this.ipProbeTimeout = timeout;
    } else {
      this.ipProbeEnabled = false;
      this.ipProbeTimeout = 0;
    }
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

    let route = this.getCachedRoute(host);

    if (route === 'direct') {
      this.directConnect(host, port, inSocket, logPrefix);
      return;
    }

    let hostIP: string | undefined;

    if (route === undefined && this.ipProbeEnabled && !Net.isIP(host)) {
      let probingPromiseMap = this.probingPromiseMap;

      let promise = probingPromiseMap.get(host);
      let reused = promise !== undefined;

      if (promise === undefined) {
        promise = probeDestinationIP(host, port, this.ipProbeTimeout).finally(
          () => {
            probingPromiseMap.delete(host);
          },
        );

        probingPromiseMap.set(host, promise);
      }

      hostIP = await promise;

      console.info(
        `${logPrefix} probed ip: ${hostIP ?? '-'}${reused ? ' (reused)' : ''}`,
      );
    }

    let sessionCandidate = await server.getSessionCandidate(logPrefix);

    if (inSocket.destroyed) {
      console.info(
        `${logPrefix} in socket closed before session stream acquired.`,
      );
      return;
    }

    let id: string | undefined;

    let removeServerStreamListener: () => void;

    let serverStreamListener: ServerStreamListener = (
      outConnectStream: HTTP2.ServerHttp2Stream,
      headers: HTTP2.IncomingHttpHeaders,
    ) => {
      removeServerStreamListener();

      if (inSocket.destroyed) {
        outConnectStream.destroy();
        return;
      }

      outConnectStream.respond();

      if (headers.type === 'connect-direct') {
        console.info(`${logPrefix} out routed to direct.`);

        this.setCachedRoute(host, 'direct');
        this.directConnect(host, port, inSocket, logPrefix);

        outConnectStream.end();
        return;
      }

      if (headers.type !== 'connect-ok') {
        console.error(`${logPrefix} unexpected request type ${headers.type}.`);

        writeHTTPHead(inSocket, 500, 'Internal Server Error', true);

        outConnectStream.destroy();
        return;
      }

      this.setCachedRoute(host, 'proxy');

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
    };

    sessionCandidate.stream.pushStream(
      {type: 'connect', host, port, 'host-ip': hostIP},
      (error, pushStream) => {
        if (error) {
          console.error(`${logPrefix} connect error:`, error.message);

          writeHTTPHead(inSocket, 500, 'Internal Server Error', true);
          return;
        }

        id = `${sessionCandidate.id}:${pushStream.id}`;

        removeServerStreamListener = server.onStream(id, serverStreamListener);

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

    let removeServerStreamListener: () => void;

    let serverStreamListener: ServerStreamListener = (
      outStream: HTTP2.ServerHttp2Stream,
      outHeaders: HTTP2.IncomingHttpHeaders,
    ) => {
      if (request.socket.destroyed) {
        removeServerStreamListener();
        outStream.destroy();
        return;
      }

      outStream.respond();

      if (outHeaders.type === 'request-direct') {
        removeServerStreamListener();

        console.info(`${logPrefix} out routed to direct.`);

        this.setCachedRoute(host, 'direct');
        this.directRequest(method, url, headers, request, response, logPrefix);

        outStream.end();
        return;
      }

      if (
        // This happens after 'request-response'.
        outHeaders.type === 'response-headers' ||
        outHeaders.type === 'response-headers-end'
      ) {
        removeServerStreamListener();

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
        removeServerStreamListener();

        console.error(`${logPrefix} unexpected request type ${headers.type}.`);
        response.writeHead(500).end();
        outStream.destroy();
        return;
      }

      this.setCachedRoute(host, 'proxy');

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
    };

    sessionCandidate.stream.pushStream(
      {type: 'request', method, url, headers: JSON.stringify(headers)},
      (error, pushStream) => {
        if (error) {
          response.writeHead(500).end();
          return;
        }

        id = `${sessionCandidate.id}:${pushStream.id}`;

        removeServerStreamListener = server.onStream(id, serverStreamListener);

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
