import type * as HTTP from 'http';
import * as Net from 'net';
import type {Duplex} from 'stream';

import type {InConnectLogContext, InRequestLogContext} from '../../@log.js';
import {Logs} from '../../@log.js';
import {handleErrorWhile, pipelines} from '../../@utils/index.js';
import type {TunnelId} from '../../common.js';
import type {Router} from '../router/index.js';
import type {TunnelServer} from '../tunnel-server.js';

export class NetProxyBridge {
  constructor(
    readonly tunnelServer: TunnelServer,
    readonly router: Router,
  ) {}

  async connect(
    context: InConnectLogContext,
    inSocket: Net.Socket,
    host: string,
    port: number,
    headerMap: Map<string, string>,
  ): Promise<void> {
    const referer = headerMap.get('referer');
    const hostInHeader = headerMap.get('host')?.replace(/:\d+$/, '');

    let route: TunnelId | undefined;

    try {
      route = await handleErrorWhile(
        referer !== undefined
          ? this.router.routeURL(referer)
          : this.router.routeHost(hostInHeader ?? host),
        [inSocket],
      );
    } catch (error) {
      inSocket.destroy();

      Logs.debug(context, error);

      return;
    }

    let outSocket: Duplex;

    if (route !== undefined) {
      try {
        outSocket = await this.tunnelServer.connect(
          context.id,
          route,
          host,
          port,
        );
      } catch (error) {
        inSocket.destroy();

        Logs.error(context, 'failed to establish tunnel connection.');
        Logs.debug(context, error);

        return;
      }
    } else {
      outSocket = Net.connect(port, host);
    }

    try {
      await pipelines([
        [inSocket, outSocket],
        [outSocket, inSocket],
      ]);

      Logs.info(context, 'connect socket closed.');
    } catch (error) {
      Logs.error(context, 'an error occurred proxying connect.');
      Logs.debug(context, error);
    }
  }

  async request(
    context: InRequestLogContext,
    request: HTTP.IncomingMessage,
    response: HTTP.ServerResponse,
  ): Promise<void> {
    const urlString = request.url!;

    Logs.info(context, `request ${urlString}`);

    const {host, port: portString, pathname, search, hash} = new URL(urlString);
    const port = parseInt(portString) || 80;

    const {referer} = request.headers;

    const route =
      referer !== undefined
        ? await this.router.routeURL(referer)
        : await this.router.routeHost(host);

    let socket: Duplex;

    if (route !== undefined) {
      try {
        socket = await this.tunnelServer.connect(context.id, route, host, port);
      } catch (error) {
        request.destroy();
        response.destroy();

        Logs.error(context, 'failed to establish tunnel connection.');
        Logs.debug(context, error);

        return;
      }
    } else {
      socket = Net.connect(port, host);
    }

    socket.write(
      `${request.method} ${pathname}${search}${hash} HTTP/${request.httpVersion}\r\n`,
    );

    const rawHeaders = request.rawHeaders;

    for (let index = 0; index < rawHeaders.length; index += 2) {
      const key = rawHeaders[index];
      const value = rawHeaders[index + 1];

      socket.write(`${key}: ${value}\r\n`);
    }

    socket.write('\r\n');

    try {
      await pipelines([
        [request, socket],
        [socket, response.socket!],
      ]);

      Logs.info(context, 'request socket closed.');
    } catch (error) {
      Logs.error(context, 'an error occurred proxying request.');
      Logs.debug(context, error);
    }
  }
}
