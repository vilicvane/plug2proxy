import assert from 'assert';
import * as HTTP from 'http';
import type * as Net from 'net';

import {minimatch} from 'minimatch';
import ms from 'ms';
import {UAParser} from 'ua-parser-js';
import * as x from 'x-value';

import type {InLogContext} from '../@log/index.js';
import {
  IN_ERROR_CONNECT_SOCKET_ERROR,
  IN_ERROR_REQUEST_SOCKET_ERROR,
  IN_ERROR_ROUTING_CONNECTION,
  IN_HTTP_PROXY_LISTENING_ON,
  Logs,
} from '../@log/index.js';
import {
  errorWhile,
  getURLPort,
  matchAnyHost,
  streamErrorWhileEntry,
} from '../@utils/index.js';
import type {ConnectionId} from '../common.js';
import type {ListeningHost} from '../x.js';
import {Port} from '../x.js';

import type {ReadHTTPHeadersOrTLSResult} from './@sniffing.js';
import {readHTTPHeadersOrTLS} from './@sniffing.js';
import type {NetProxyBridge, TLSProxyBridge} from './proxy-bridges/index.js';
import type {RouteCandidate, Router} from './router/index.js';
import {WEB_HOSTNAME, type Web} from './web.js';

const CONNECT_SOCKET_TIMEOUT = ms('30s');

const HOST_DEFAULT = '';
const PORT_DEFAULT_START_NUMBER = 8000;

export const HTTP_PROXY_REFERER_SNIFFING_OPTIONS_DEFAULT = false;

export const HTTPProxyRefererSniffingOptions = x.object({
  include: x
    .object({
      browsers: x.array(x.string).optional(),
      hosts: x.array(x.string).optional(),
    })
    .optional(),
  exclude: x
    .object({
      browsers: x.array(x.string).optional(),
      hosts: x.array(x.string).optional(),
    })
    .optional(),
});

export type HTTPProxyRefererSniffingOptions = x.TypeOf<
  typeof HTTPProxyRefererSniffingOptions
>;

export type HTTPProxyOptions = {
  host?: ListeningHost;
  port?: Port;
  refererSniffing?: HTTPProxyRefererSniffingOptions | boolean;
};

export class HTTPProxy {
  readonly server: HTTP.Server;

  private lastContextIdNumber = 0;

  /**
   * Sockets kept alive.
   */
  private handledRequestSocketSet = new WeakSet<Net.Socket>();

  private refererSniffingOptions:
    | Required<HTTPProxyRefererSniffingOptions>
    | undefined;

  constructor(
    index: number,
    readonly netProxyBridge: NetProxyBridge,
    readonly tlsProxyBridge: TLSProxyBridge | undefined,
    readonly router: Router,
    readonly web: Web,
    {
      host = HOST_DEFAULT,
      port = Port.nominalize(PORT_DEFAULT_START_NUMBER + index),
      refererSniffing:
        refererSniffingOptions = HTTP_PROXY_REFERER_SNIFFING_OPTIONS_DEFAULT,
    }: HTTPProxyOptions,
  ) {
    if (refererSniffingOptions === true) {
      refererSniffingOptions = {};
    }

    if (refererSniffingOptions) {
      this.refererSniffingOptions = {
        include: refererSniffingOptions.include ?? {},
        exclude: refererSniffingOptions.exclude ?? {},
      };
    }

    this.server = HTTP.createServer()
      .on(
        'connect',
        (request, connectSocket: Net.Socket) =>
          void this.connect(request, connectSocket),
      )
      .on(
        'request',
        (request, response) => void this.request(request, response),
      )
      .listen(port, host, () => {
        Logs.info('proxy', IN_HTTP_PROXY_LISTENING_ON(host, port));
      });
  }

  private async connect(
    request: HTTP.IncomingMessage,
    connectSocket: Net.Socket,
  ): Promise<void> {
    connectSocket
      .setTimeout(CONNECT_SOCKET_TIMEOUT)
      .on('timeout', () => connectSocket.destroy());

    const [host, portString] = request.url!.split(':');
    const port = parseInt(portString);

    assert(!isNaN(port));

    connectSocket.write('HTTP/1.1 200 OK\r\n\r\n');

    const connectionId = this.getNextConnectionId();

    const context: InLogContext = {
      type: 'in',
      method: 'connect',
      connection: connectionId,
      host: `${host}:${port}`,
    };

    const {refererSniffingOptions, netProxyBridge, tlsProxyBridge} = this;

    let hostname: string;
    let referer: string | undefined;

    let peekingResult: ReadHTTPHeadersOrTLSResult | undefined;

    if (refererSniffingOptions) {
      const {include, exclude} = refererSniffingOptions;

      const {
        browser: {name: browserName},
      } = new UAParser(request.headers['user-agent']).getResult();

      const matched =
        browserName !== undefined &&
        (include.browsers?.some(pattern => minimatch(browserName, pattern)) ??
          true) &&
        !(exclude.browsers ?? []).some(pattern =>
          minimatch(browserName, pattern),
        );

      peekingResult = matched
        ? await readHTTPHeadersOrTLS(connectSocket)
        : undefined;

      switch (peekingResult?.type) {
        case 'http1':
        case 'http2':
          hostname =
            peekingResult.headerMap.get('host')?.replace(/:\d+$/, '') ?? host;
          referer = peekingResult.headerMap.get('referer');
          break;
        case 'tls':
          hostname = peekingResult.serverName ?? host;
          break;
        default:
          hostname = host;
          break;
      }
    } else {
      hostname = host;
    }

    const connectSocketErrorWhile = streamErrorWhileEntry(
      connectSocket,
      error => Logs.error(context, IN_ERROR_CONNECT_SOCKET_ERROR(error)),
    );

    let route: RouteCandidate | undefined;
    let ignoreReferer: boolean;

    try {
      [route, ignoreReferer] = await errorWhile(
        this.preRoute(hostname, port),
        () => Logs.error(context, IN_ERROR_ROUTING_CONNECTION),
        [connectSocketErrorWhile],
      );
    } catch (error) {
      Logs.debug(context, error);
      return;
    }

    if (ignoreReferer) {
      return netProxyBridge.connect(
        context,
        connectSocket,
        host,
        port,
        route,
        undefined,
      );
    }

    if (peekingResult?.type === 'tls' && tlsProxyBridge) {
      const {include, exclude} = refererSniffingOptions!;
      const {serverName} = peekingResult;

      const matchingHost =
        (include.hosts
          ? matchAnyHost([host, serverName], include.hosts)
          : true) &&
        !(exclude.hosts
          ? matchAnyHost([host, serverName], exclude.hosts)
          : false);

      if (matchingHost) {
        return tlsProxyBridge.connect(
          context,
          connectSocket,
          host,
          port,
          peekingResult,
          route,
        );
      }
    }

    return netProxyBridge.connect(
      context,
      connectSocket,
      host,
      port,
      route,
      referer,
    );
  }

  private async request(
    request: HTTP.IncomingMessage,
    response: HTTP.ServerResponse,
  ): Promise<void> {
    const urlString = request.url!;
    const requestSocket = request.socket;

    let url: URL | undefined;

    try {
      url = new URL(urlString);
    } catch {
      // ignore
    }

    if (url === undefined || url.host === WEB_HOSTNAME) {
      this.web.app(request, response);
      return;
    }

    const {handledRequestSocketSet} = this;

    if (handledRequestSocketSet.has(requestSocket)) {
      return;
    }

    handledRequestSocketSet.add(requestSocket);

    const connectionId = this.getNextConnectionId();

    const context: InLogContext = {
      type: 'in',
      method: 'request',
      connection: connectionId,
      host: url.host,
    };

    const requestSocketErrorWhile = streamErrorWhileEntry(
      requestSocket,
      error => Logs.error(context, IN_ERROR_REQUEST_SOCKET_ERROR(error)),
    );

    const port = getURLPort(url);

    let route: RouteCandidate | undefined;
    let ignoreReferer: boolean;

    try {
      [route, ignoreReferer] = await errorWhile(
        this.preRoute(url.hostname, port),
        () => Logs.error(context, IN_ERROR_ROUTING_CONNECTION),
        [requestSocketErrorWhile],
      );
    } catch (error) {
      Logs.debug(context, error);
      return;
    }

    await this.netProxyBridge.request(
      context,
      request,
      route,
      ignoreReferer ? undefined : request.headers.referer,
    );
  }

  private async preRoute(
    hostname: string,
    port: number,
  ): Promise<[route: RouteCandidate | undefined, ignoreReferer: boolean]> {
    const {router} = this;

    const route = await router.routeHost(hostname, port);

    const routeWithoutResolvingIP = await router.routeHost(
      hostname,
      port,
      false,
    );

    return [
      route,
      // Ignore referer if the route is dominated by an explicit rule (result
      // with/without resolving the IP is the same).
      routeWithoutResolvingIP !== undefined &&
        routeWithoutResolvingIP.remote === route?.remote,
    ];
  }

  private getNextConnectionId(): ConnectionId {
    return ++this.lastContextIdNumber as ConnectionId;
  }
}
