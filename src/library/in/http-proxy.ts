import * as HTTP from 'http';
import type * as Net from 'net';

import type {TLSProxyOptions} from './@tls-proxy.js';
import {TLSProxy} from './@tls-proxy.js';

export type HTTPProxyOptions = TLSProxyOptions & {
  host: string;
  port: number;
};

export class HTTPProxy extends TLSProxy {
  readonly httpServer: HTTP.Server;

  constructor({host, port, ...options}: HTTPProxyOptions) {
    super(options);

    this.httpServer = HTTP.createServer()
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

    this.connect(inSocket, host, port);
  };

  private onHTTPServerRequest = (): void => {};
}