import * as HTTP from 'http';
import * as Net from 'net';
import * as OS from 'os';
import {URL} from 'url';

import {HOP_BY_HOP_HEADERS_REGEX} from '../@common';
import {groupRawHeaders} from '../@utils';
import {debugConnect, debugRequest} from '../debug';
import {InOutConnectOptions} from '../types';

import {InServer} from './in-server';

const HOSTNAME = OS.hostname();

const {
  name: PACKAGE_NAME,
  version: PACKAGE_VERSION,
  // eslint-disable-next-line @typescript-eslint/no-require-imports,@typescript-eslint/no-var-requires
} = require('../../../package.json');

const VIA = `1.1 ${HOSTNAME} (${PACKAGE_NAME}/${PACKAGE_VERSION})`;

export interface InProxyOptions {
  listen: Net.ListenOptions;
}

export class InProxy {
  readonly proxyServer: HTTP.Server;

  constructor(readonly inServer: InServer, readonly options: InProxyOptions) {
    let server = HTTP.createServer();

    server.listen(options.listen);

    server.on('connect', this.onConnect);
    server.on('request', this.onRequest);

    this.proxyServer = server;
  }

  private onConnect = (
    request: HTTP.IncomingMessage,
    socket: Net.Socket,
  ): void => {
    void this.connect(request, socket);
  };

  private onRequest = (
    request: HTTP.IncomingMessage,
    response: HTTP.ServerResponse,
  ): void => {
    void this.request(request, response);
  };

  private async connect(
    request: HTTP.IncomingMessage,
    inSocket: Net.Socket,
  ): Promise<void> {
    let url = request.url!;

    inSocket.on('end', () => {
      debugConnect('in socket ended %s', url);
    });

    inSocket.on('error', error => {
      debugConnect(
        'in socket error %s %s',
        (error as any).code ?? error.message,
        url,
      );
    });

    let [host, portString] = url.split(':');

    let port = Number(portString) || 443;

    let options: InOutConnectOptions = {
      host,
      port,
    };

    debugConnect('connect %s:%d', host, port);

    await this.inServer.connect(options, inSocket);
  }

  private async request(
    request: HTTP.IncomingMessage,
    response: HTTP.ServerResponse,
  ): Promise<void> {
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

    await this.inServer.request(
      {
        method,
        url,
        headers,
      },
      request,
      response,
    );
  }
}
