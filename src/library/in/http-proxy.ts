import * as HTTP from 'http';
import type * as Net from 'net';

import * as x from 'x-value';

import type {InConnectLogContext, InRequestLogContext} from '../@log.js';
import {Logs} from '../@log.js';
import {readHTTPRequestStreamHeaders} from '../@utils/index.js';
import type {ConnectionId} from '../common.js';
import {ListeningHost, ListeningPort} from '../x.js';

import type {NetProxyBridge, TLSProxyBridge} from './proxy-bridges/index.js';
import type {TunnelServer} from './tunnel-server.js';
import {WEB_HOSTNAME, type Web} from './web.js';

export const HTTPProxyOptions = x.object({
  host: ListeningHost.optional(),
  port: ListeningPort.optional(),
});

export type HTTPProxyOptions = x.TypeOf<typeof HTTPProxyOptions>;

export class HTTPProxy {
  readonly server: HTTP.Server;

  private lastContextIdNumber = 0;

  constructor(
    readonly tunnelServer: TunnelServer,
    readonly tlsProxyBridge: TLSProxyBridge,
    readonly netProxyBridge: NetProxyBridge,
    readonly web: Web,
    {host, port}: HTTPProxyOptions,
  ) {
    this.server = HTTP.createServer()
      .on('connect', this.onHTTPServerConnect)
      .on('request', this.onHTTPServerRequest)
      .listen(port, host);
  }

  private onHTTPServerConnect = (
    request: HTTP.IncomingMessage,
    socket: Net.Socket,
  ): void => {
    const [host, portString] = request.url!.split(':');
    const port = parseInt(portString) || 443;

    socket.write('HTTP/1.1 200 OK\r\n\r\n');

    const context: InConnectLogContext = {
      type: 'in:connect',
      id: this.getNextContextId(),
      host,
      port,
    };

    void readHTTPRequestStreamHeaders(socket).then(
      headerMap => {
        if (headerMap) {
          void this.netProxyBridge.connect(
            context,
            socket,
            host,
            port,
            headerMap,
          );
        } else {
          void this.tlsProxyBridge.connect(context, socket, host, port);
        }
      },
      (error: unknown) => {
        socket.destroy();

        Logs.error(context, 'error detecting socket type');
        Logs.debug(context, error);
      },
    );
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

    if (url === undefined || url.hostname === WEB_HOSTNAME) {
      this.web.app(request, response);
      return;
    }

    const context: InRequestLogContext = {
      type: 'in:request',
      id: this.getNextContextId(),
      url: urlString,
    };

    void this.netProxyBridge.request(context, request, response);
  };

  private getNextContextId(): ConnectionId {
    return ++this.lastContextIdNumber as ConnectionId;
  }
}
