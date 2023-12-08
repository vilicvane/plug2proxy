import type * as HTTP from 'http';
import * as Net from 'net';
import type {Duplex} from 'stream';

import type {InLogContext} from '../../@log/index.js';
import {
  IN_CONNECT_NET,
  IN_CONNECT_SOCKET_CLOSED,
  IN_ERROR_CONNECT_SOCKET_ERROR,
  IN_ERROR_PIPING_CONNECT_SOCKET_FROM_TO_TUNNEL,
  IN_ERROR_PIPING_REQUEST_SOCKET_FROM_TO_TUNNEL,
  IN_ERROR_REQUEST_SOCKET_ERROR,
  IN_ERROR_ROUTING_CONNECTION,
  IN_ERROR_TUNNEL_CONNECTING,
  IN_REQUEST_NET,
  IN_REQUEST_SOCKET_CLOSED,
  Logs,
} from '../../@log/index.js';
import {
  errorWhile,
  pipelines,
  streamErrorWhileEntry,
} from '../../@utils/index.js';
import type {RouteCandidate, Router} from '../router/index.js';
import type {TunnelServer} from '../tunnel-server.js';

export class NetProxyBridge {
  constructor(
    readonly tunnelServer: TunnelServer,
    readonly router: Router,
  ) {}

  async connect(
    context: InLogContext,
    connectSocket: Net.Socket,
    host: string,
    port: number,
    headerMap: Map<string, string> | undefined,
  ): Promise<void> {
    Logs.info(context, IN_CONNECT_NET(host, port));

    const connectSocketErrorWhile = streamErrorWhileEntry(
      connectSocket,
      error => Logs.error(context, IN_ERROR_CONNECT_SOCKET_ERROR(error)),
    );

    const referer = headerMap?.get('referer');
    const hostInHeader = headerMap?.get('host')?.replace(/:\d+$/, '');

    let route: RouteCandidate | undefined;

    try {
      route = await errorWhile(
        this.router.route(hostInHeader ?? host, referer),
        () => Logs.error(context, IN_ERROR_ROUTING_CONNECTION),
        [connectSocketErrorWhile],
      );
    } catch (error) {
      Logs.debug(context, error);
      return;
    }

    let tunnel: Duplex;

    if (route) {
      try {
        tunnel = await errorWhile(
          this.tunnelServer.connect(context, route, host, port),
          error => Logs.error(context, IN_ERROR_TUNNEL_CONNECTING(error)),
          [connectSocketErrorWhile],
        );
      } catch (error) {
        Logs.debug(context, error);
        return;
      }
    } else {
      tunnel = Net.connect(port, host);
    }

    try {
      await pipelines([
        [connectSocket, tunnel],
        [tunnel, connectSocket],
      ]);

      Logs.info(context, IN_CONNECT_SOCKET_CLOSED);
    } catch (error) {
      Logs.error(context, IN_ERROR_PIPING_CONNECT_SOCKET_FROM_TO_TUNNEL(error));
      Logs.debug(context, error);
    }
  }

  async request(
    context: InLogContext,
    request: HTTP.IncomingMessage,
  ): Promise<void> {
    const urlString = request.url!;

    Logs.info(context, IN_REQUEST_NET(urlString));

    const requestSocketErrorWhile = streamErrorWhileEntry(
      request.socket,
      error => Logs.error(context, IN_ERROR_REQUEST_SOCKET_ERROR(error)),
    );

    const {host, port: portString, pathname, search, hash} = new URL(urlString);
    const port = parseInt(portString) || 80;

    const {referer} = request.headers;

    let route: RouteCandidate | undefined;

    try {
      route = await errorWhile(
        this.router.route(host, referer),
        () => Logs.error(context, IN_ERROR_ROUTING_CONNECTION),
        [requestSocketErrorWhile],
      );
    } catch (error) {
      Logs.debug(context, error);
      return;
    }

    let socket: Duplex;

    if (route) {
      try {
        socket = await errorWhile(
          this.tunnelServer.connect(context, route, host, port),
          error => Logs.error(context, IN_ERROR_TUNNEL_CONNECTING(error)),
          [requestSocketErrorWhile],
        );
      } catch (error) {
        Logs.debug(context, error);
        return;
      }
    } else {
      socket = Net.connect(port, host);
    }

    const uri = `${pathname}${search}${hash}`;

    socket.write(`${request.method} ${uri} HTTP/${request.httpVersion}\r\n`);

    const {rawHeaders} = request;

    for (let index = 0; index < rawHeaders.length; index += 2) {
      const key = rawHeaders[index];
      const value = rawHeaders[index + 1];

      socket.write(`${key}: ${value}\r\n`);
    }

    socket.write('\r\n');

    try {
      await pipelines([
        [request.socket, socket],
        [socket, request.socket],
      ]);

      Logs.info(context, IN_REQUEST_SOCKET_CLOSED);
    } catch (error) {
      Logs.error(context, IN_ERROR_PIPING_REQUEST_SOCKET_FROM_TO_TUNNEL(error));
      Logs.debug(context, error);
    }
  }
}
