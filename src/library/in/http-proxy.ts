import assert from 'assert';
import * as HTTP from 'http';
import type * as Net from 'net';

import type {InLogContext} from '../@log/index.js';
import {
  IN_ERROR_DETECTING_CONNECT_TYPE,
  IN_HTTP_PROXY_LISTENING_ON,
  Logs,
} from '../@log/index.js';
import type {ConnectionId} from '../common.js';
import type {ListeningHost} from '../x.js';
import {Port} from '../x.js';

import {readHTTPHeadersOrTLS} from './@sniffing.js';
import type {NetProxyBridge, TLSProxyBridge} from './proxy-bridges/index.js';
import type {TunnelServer} from './tunnel-server.js';
import {WEB_HOSTNAME, type Web} from './web.js';

const HOST_DEFAULT = '';
const PORT_DEFAULT = Port.nominalize(8000);

export type HTTPProxyOptions = {
  host?: ListeningHost;
  port?: Port;
};

export class HTTPProxy {
  readonly server: HTTP.Server;

  private lastContextIdNumber = 0;

  /**
   * Sockets kept alive.
   */
  private handledRequestSocketSet = new WeakSet<Net.Socket>();

  constructor(
    readonly tunnelServer: TunnelServer,
    readonly tlsProxyBridge: TLSProxyBridge,
    readonly netProxyBridge: NetProxyBridge,
    readonly web: Web,
    {host = HOST_DEFAULT, port = PORT_DEFAULT}: HTTPProxyOptions,
  ) {
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
    const [host, portString] = request.url!.split(':');
    const port = parseInt(portString);

    assert(!isNaN(port));

    connectSocket.write('HTTP/1.1 200 OK\r\n\r\n');

    const connectionId = this.getNextConnectionId();

    const context: InLogContext = {
      type: 'in',
      method: 'connect',
      connection: connectionId,
      hostname: `${host}:${port}`,
    };

    void readHTTPHeadersOrTLS(connectSocket).then(
      result => {
        if (result && result.type === 'tls') {
          void this.tlsProxyBridge.connect(
            context,
            connectionId,
            connectSocket,
            host,
            port,
            result,
          );
        } else {
          void this.netProxyBridge.connect(
            context,
            connectSocket,
            host,
            port,
            result?.headerMap,
          );
        }
      },
      (error: unknown) => {
        connectSocket.destroy();

        Logs.error(context, IN_ERROR_DETECTING_CONNECT_TYPE);
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

    const {handledRequestSocketSet} = this;

    if (handledRequestSocketSet.has(request.socket)) {
      return;
    }

    handledRequestSocketSet.add(request.socket);

    const connectionId = this.getNextConnectionId();

    const context: InLogContext = {
      type: 'in',
      method: 'request',
      connection: connectionId,
      hostname: url.hostname,
    };

    void this.netProxyBridge.request(context, connectionId, request);
  };

  private getNextConnectionId(): ConnectionId {
    return ++this.lastContextIdNumber as ConnectionId;
  }
}
