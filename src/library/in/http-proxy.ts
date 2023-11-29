import * as HTTP from 'http';
import type * as Net from 'net';

import * as x from 'x-value';

import {IPPattern, Port} from '../x.js';

import type {TLSProxy} from './tls-proxy.js';

export const HTTPProxyOptions = x.object({
  host: x.union([IPPattern, x.literal('')]).optional(),
  port: Port.optional(),
});

export type HTTPProxyOptions = x.TypeOf<typeof HTTPProxyOptions>;

export class HTTPProxy {
  readonly server: HTTP.Server;

  private lastContextId = 0;

  constructor(
    readonly tlsProxy: TLSProxy,
    {host, port}: HTTPProxyOptions,
  ) {
    this.server = HTTP.createServer()
      .on('connect', this.onHTTPServerConnect)
      .on('request', this.onHTTPServerRequest)
      .listen(port, host);
  }

  private onHTTPServerConnect = (
    request: HTTP.IncomingMessage,
    inSocket: Net.Socket,
  ): void => {
    const [host, portString] = request.url!.split(':');
    const port = parseInt(portString) || 443;

    inSocket.write(`HTTP/1.1 200 OK\r\n\r\n`);

    this.tlsProxy.connect(++this.lastContextId, inSocket, host, port);
  };

  private onHTTPServerRequest = (): void => {};
}
