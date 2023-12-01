import assert from 'assert';
import * as HTTP2 from 'http2';
import type {Duplex} from 'stream';

import Chalk from 'chalk';
import type {Duplexify} from 'duplexify';
import duplexify from 'duplexify';
import * as x from 'x-value';
import * as xn from 'x-value/node';

import type {
  InTunnelConnectLogContext,
  InTunnelLogContext,
  LogContext,
} from '../@log.js';
import {Logs} from '../@log.js';
import {setupSessionPing} from '../@utils/index.js';
import type {
  ConnectionId,
  TunnelId,
  TunnelInOutHeaderData,
  TunnelOutInHeaderData,
  TunnelStreamId,
} from '../common.js';
import {
  CONNECTION_WINDOW_SIZE,
  STREAM_WINDOW_SIZE,
  TUNNEL_HEADER_NAME,
} from '../common.js';
import {IPPattern, Port} from '../x.js';

import type {Router} from './router/index.js';

const CONTEXT: LogContext = {
  type: 'in:tunnel-server',
};

const MAX_OUTSTANDING_PINGS = 5;

const HOST_DEFAULT = '';
const PORT_DEFAULT = Port.nominalize(8443);

export const TunnelServerOptions = x.object({
  host: x.union([IPPattern, x.literal('')]).optional(),
  port: Port.optional(),
  cert: x.union([x.string, xn.Buffer]).optional(),
  key: x.union([x.string, xn.Buffer]).optional(),
  password: x.string.optional(),
});

export type TunnelServerOptions = x.TypeOf<typeof TunnelServerOptions>;

export class TunnelServer {
  readonly server: HTTP2.Http2SecureServer;

  private tunnelMap = new Map<TunnelId, Tunnel>();
  private sessionToTunnelIdMap = new Map<HTTP2.Http2Session, TunnelId>();

  constructor(
    readonly router: Router,
    {
      host = HOST_DEFAULT,
      port = PORT_DEFAULT,
      cert,
      key,
      password,
    }: TunnelServerOptions,
  ) {
    this.server = HTTP2.createSecureServer({
      settings: {
        initialWindowSize: STREAM_WINDOW_SIZE,
      },
      cert,
      key,
      maxOutstandingPings: MAX_OUTSTANDING_PINGS,
    })
      .on('session', session => {
        session.setLocalWindowSize(CONNECTION_WINDOW_SIZE);

        setupSessionPing(session);
      })
      .on('stream', (stream, headers) => {
        const data = JSON.parse(
          headers[TUNNEL_HEADER_NAME] as string,
        ) as TunnelOutInHeaderData;

        switch (data.type) {
          case 'tunnel':
            this.handleTunnel(data, stream);
            break;
          case 'out-in-stream':
            this.handleOutInStream(data, stream);
            break;
        }
      })
      .listen(port, host, () => {
        Logs.info(CONTEXT, `listening on ${host}:${port}...`);
      });
  }

  async connect(
    connectionId: ConnectionId,
    tunnelId: TunnelId,
    host: string,
    port: number,
  ): Promise<Duplex> {
    const tunnel = this.tunnelMap.get(tunnelId);

    assert(tunnel);

    const {tunnelStream} = tunnel;

    const id = ++tunnel.lastStreamIdNumber as TunnelStreamId;

    const context: InTunnelConnectLogContext = {
      type: 'in:tunnel-connect',
      connection: connectionId,
      tunnel: tunnelId,
      stream: id,
    };

    Logs.info(
      context,
      `${Chalk.cyan('tunnel connect')} ${host}:${port} via ${Chalk.yellow(
        tunnel.remoteAddress,
      )}...`,
    );

    return new Promise((resolve, reject) => {
      tunnelStream.pushStream(
        {
          [TUNNEL_HEADER_NAME]: JSON.stringify({
            type: 'in-out-stream',
            id,
            host,
            port,
          } satisfies TunnelInOutHeaderData),
        },
        (error, inOutStream) => {
          if (error) {
            reject(error);
            return;
          }

          Logs.debug(context, 'established IN-OUT stream.');

          const stream = duplexify(inOutStream);

          tunnel.connectionMap.set(id, {
            context,
            stream,
          });

          stream.on('error', error => {
            Logs.warn(context, 'error IN-OUT stream.');
            Logs.debug(context, error);
          });

          stream.on('close', () => {
            Logs.debug(context, 'closed IN-OUT stream.');

            tunnel.connectionMap.delete(id);
          });

          resolve(stream);
        },
      );
    });
  }

  private handleTunnel(
    {routeMatchOptions}: TunnelOutInHeaderData & {type: 'tunnel'},
    stream: HTTP2.ServerHttp2Stream,
  ): void {
    const session = stream.session;

    assert(session);

    let id = this.sessionToTunnelIdMap.get(session);

    if (id === undefined) {
      id = this.getNextTunnelId();

      const context: InTunnelLogContext = {
        type: 'in:tunnel',
        id,
      };

      this.tunnelMap.set(id, {
        id,
        remoteAddress: session.socket!.remoteAddress!,
        tunnelStream: stream,
        connectionMap: new Map(),
        lastStreamIdNumber: 0,
      });

      assert(stream.session);

      this.sessionToTunnelIdMap.set(stream.session, id);

      this.router.register(
        id,
        stream.session.socket!.remoteAddress!,
        routeMatchOptions,
      );

      stream.on('error', error => {
        Logs.warn(context, 'an error occurred with tunnel stream.');
        Logs.debug(context, error);
      });

      stream.on('close', () => {
        this.tunnelMap.delete(id!);
        this.sessionToTunnelIdMap.delete(session);
        this.router.unregister(id!);

        Logs.info(context, 'tunnel closed.');
      });

      stream.respond({':status': 200});

      Logs.info(context, 'tunnel established.');
      Logs.debug(context, 'route match options:', routeMatchOptions);
    } else {
      const context: InTunnelLogContext = {
        type: 'in:tunnel',
        id,
      };

      const tunnel = this.tunnelMap.get(id);

      assert(tunnel);

      this.router.update(id, routeMatchOptions);

      stream.respond({':status': 200}, {endStream: true});

      Logs.info(context, 'tunnel updated.');
      Logs.debug(context, 'route match options:', routeMatchOptions);
    }
  }

  private handleOutInStream(
    {id}: TunnelOutInHeaderData & {type: 'out-in-stream'},
    stream: HTTP2.ServerHttp2Stream,
  ): void {
    assert(stream.session);

    const tunnelId = this.sessionToTunnelIdMap.get(stream.session);

    assert(tunnelId);

    const connection = this.tunnelMap.get(tunnelId)?.connectionMap.get(id);

    assert(connection);

    Logs.debug(connection.context, 'established OUT-IN stream.');

    connection.stream.setReadable(stream);

    stream.respond({':status': 200});
  }

  private lastTunnelIdNumber = 0;

  private getNextTunnelId(): TunnelId {
    return ++this.lastTunnelIdNumber as TunnelId;
  }
}

export type TunnelConnection = {
  context: LogContext;
  stream: Duplexify;
};

export type Tunnel = {
  id: TunnelId;
  remoteAddress: string;
  tunnelStream: HTTP2.ServerHttp2Stream;
  connectionMap: Map<TunnelStreamId, TunnelConnection>;
  lastStreamIdNumber: number;
};
