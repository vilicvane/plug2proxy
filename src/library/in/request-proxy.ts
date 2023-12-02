import type * as HTTP from 'http';
import * as Net from 'net';
import type {Duplex} from 'stream';
import {pipeline} from 'stream/promises';

import Chalk from 'chalk';

import type {InRequestLogContext} from '../@log.js';
import {Logs} from '../@log.js';
import {getErrorCode} from '../@utils/index.js';
import type {ConnectionId} from '../common.js';

import type {Router} from './router/index.js';
import type {TunnelServer} from './tunnel-server.js';

export class RequestProxy {
  constructor(
    readonly tunnelServer: TunnelServer,
    readonly router: Router,
  ) {}

  async request(
    id: ConnectionId,
    request: HTTP.IncomingMessage,
    response: HTTP.ServerResponse,
    url: string,
  ): Promise<void> {
    const context: InRequestLogContext = {
      type: 'in:request',
      id,
      url,
    };

    Logs.info(context, `${Chalk.cyan('request')} ${url}`);

    const {host, port: portString, pathname, search, hash} = new URL(url);
    const port = parseInt(portString) || 80;

    const {referer} = request.headers;

    const route =
      referer !== undefined
        ? await this.router.routeURL(referer)
        : await this.router.routeHost(host);

    let socket: Duplex;

    if (route !== undefined) {
      try {
        socket = await this.tunnelServer.connect(id, route, host, port);
      } catch (error) {
        Logs.error(context, 'failed to establish tunnel connection.');
        Logs.debug(context, error);

        request.destroy();
        response.destroy();

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
      await Promise.all([
        pipeline(request, socket),
        pipeline(socket, response.socket!),
      ]);

      Logs.info(context, 'request socket closed.');
    } catch (error) {
      request.destroy();
      response.destroy();

      if (getErrorCode(error) === 'ERR_STREAM_PREMATURE_CLOSE') {
        Logs.info(context, 'request socket closed.');
      } else {
        Logs.error(context, 'an error occurred proxying request.');
        Logs.debug(context, error);
      }
    }
  }
}
