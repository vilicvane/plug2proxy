import assert from 'assert';
import * as HTTP from 'http';
import type * as Net from 'net';

import {minimatch} from 'minimatch';
import ms from 'ms';
import {UAParser} from 'ua-parser-js';
import * as x from 'x-value';

import type {InLogContext} from '../@log/index.js';
import {IN_HTTP_PROXY_LISTENING_ON, Logs} from '../@log/index.js';
import {matchHost} from '../@utils/index.js';
import type {ConnectionId} from '../common.js';
import type {ListeningHost} from '../x.js';
import {Port} from '../x.js';

import type {ReadHTTPHeadersOrTLSResult} from './@sniffing.js';
import {readHTTPHeadersOrTLS} from './@sniffing.js';
import type {NetProxyBridge, TLSProxyBridge} from './proxy-bridges/index.js';
import type {TunnelServer} from './tunnel-server.js';
import {WEB_HOSTNAME, type Web} from './web.js';

const CONNECT_SOCKET_TIMEOUT = ms('30s');

const HOST_DEFAULT = '';
const PORT_DEFAULT = Port.nominalize(8000);

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
    readonly tunnelServer: TunnelServer,
    readonly tlsProxyBridge: TLSProxyBridge,
    readonly netProxyBridge: NetProxyBridge,
    readonly web: Web,
    {
      host = HOST_DEFAULT,
      port = PORT_DEFAULT,
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
      .on('connect', this.onHTTPServerConnect)
      .on('request', this.onHTTPServerRequest)
      .listen(port, host, () => {
        Logs.info('proxy', IN_HTTP_PROXY_LISTENING_ON(host, port));
      });
  }

  private onHTTPServerConnect = (
    request: HTTP.IncomingMessage,
    connectSocket: Net.Socket,
  ): void => {
    connectSocket
      .setTimeout(CONNECT_SOCKET_TIMEOUT)
      .on('timeout', () => connectSocket.destroy());

    const ua = new UAParser(request.headers['user-agent']).getResult();

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

    void (async () => {
      const {refererSniffingOptions} = this;

      let peekingResult: ReadHTTPHeadersOrTLSResult | undefined;

      if (refererSniffingOptions) {
        const {include, exclude} = refererSniffingOptions;

        const browserName = ua.browser.name;

        const matchingBrowser =
          browserName !== undefined &&
          (include.browsers?.some(pattern => minimatch(browserName, pattern)) ??
            true) &&
          !(exclude.browsers ?? []).some(pattern =>
            minimatch(browserName, pattern),
          );

        peekingResult = matchingBrowser
          ? await readHTTPHeadersOrTLS(connectSocket)
          : undefined;

        if (peekingResult && peekingResult.type === 'tls') {
          const {serverName} = peekingResult;

          const matchingHost =
            (include.hosts
              ? include.hosts.some(pattern => matchHost(host, pattern)) ||
                (serverName !== undefined &&
                  serverName !== host &&
                  include.hosts.some(pattern => matchHost(serverName, pattern)))
              : true) &&
            !(exclude.hosts
              ? exclude.hosts.some(pattern => matchHost(host, pattern)) ||
                (serverName !== undefined &&
                  serverName !== host &&
                  exclude.hosts.some(pattern => matchHost(serverName, pattern)))
              : false);

          if (matchingHost) {
            await this.tlsProxyBridge.connect(
              context,
              connectSocket,
              host,
              port,
              peekingResult,
            );

            return;
          }
        }
      }

      await this.netProxyBridge.connect(
        context,
        connectSocket,
        host,
        port,
        peekingResult &&
          (peekingResult.type === 'http1' || peekingResult.type === 'http2')
          ? peekingResult.headerMap
          : undefined,
      );
    })();
  };

  private onHTTPServerRequest = (
    request: HTTP.IncomingMessage,
    response: HTTP.ServerResponse,
  ): void => {
    const urlString = request.url!;

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

    if (handledRequestSocketSet.has(request.socket)) {
      return;
    }

    handledRequestSocketSet.add(request.socket);

    request.socket.setMaxListeners(20);

    const connectionId = this.getNextConnectionId();

    const context: InLogContext = {
      type: 'in',
      method: 'request',
      connection: connectionId,
      host: url.host,
    };

    void this.netProxyBridge.request(context, request);
  };

  private getNextConnectionId(): ConnectionId {
    return ++this.lastContextIdNumber as ConnectionId;
  }
}
