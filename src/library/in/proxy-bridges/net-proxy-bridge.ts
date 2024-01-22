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
  getURLPort,
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
    route: RouteCandidate | undefined,
    referer: string | undefined,
  ): Promise<void> {
    Logs.info(
      context,
      IN_CONNECT_NET(host, port, connectSocket.remoteAddress!),
    );

    const connectSocketErrorWhile = streamErrorWhileEntry(
      connectSocket,
      error => Logs.error(context, IN_ERROR_CONNECT_SOCKET_ERROR(error)),
    );

    if (referer !== undefined) {
      try {
        route =
          (await errorWhile(
            this.router.routeURL(referer),
            () => Logs.error(context, IN_ERROR_ROUTING_CONNECTION),
            [connectSocketErrorWhile],
          )) ?? route;
      } catch (error) {
        Logs.debug(context, error);
        return;
      }
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
    route: RouteCandidate | undefined,
    referer: string | undefined,
  ): Promise<void> {
    const urlString = request.url!;
    const requestSocket = request.socket;

    Logs.info(context, IN_REQUEST_NET(urlString, requestSocket.remoteAddress!));

    const requestSocketErrorWhile = streamErrorWhileEntry(
      requestSocket,
      error => Logs.error(context, IN_ERROR_REQUEST_SOCKET_ERROR(error)),
    );

    const urlObject = new URL(urlString);

    const {hostname, pathname, search, hash} = urlObject;

    if (referer !== undefined) {
      try {
        route =
          (await errorWhile(
            this.router.routeURL(referer),
            () => Logs.error(context, IN_ERROR_ROUTING_CONNECTION),
            [requestSocketErrorWhile],
          )) ?? route;
      } catch (error) {
        Logs.debug(context, error);
        return;
      }
    }

    const port = getURLPort(urlObject);

    let socket: Duplex;

    if (route) {
      try {
        socket = await errorWhile(
          this.tunnelServer.connect(context, route, hostname, port),
          error => Logs.error(context, IN_ERROR_TUNNEL_CONNECTING(error)),
          [requestSocketErrorWhile],
        );
      } catch (error) {
        Logs.debug(context, error);
        return;
      }
    } else {
      socket = Net.connect(port, hostname);
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
        [requestSocket, socket],
        [socket, requestSocket],
      ]);

      Logs.info(context, IN_REQUEST_SOCKET_CLOSED);
    } catch (error) {
      Logs.error(context, IN_ERROR_PIPING_REQUEST_SOCKET_FROM_TO_TUNNEL(error));
      Logs.debug(context, error);
    }
  }
}
