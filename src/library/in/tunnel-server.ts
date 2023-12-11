import assert from 'assert';
import * as HTTP2 from 'http2';
import type {Duplex, Readable} from 'stream';

import duplexer3 from 'duplexer3';

import type {InLogContext} from '../@log/index.js';
import {
  IN_ROUTE_MATCH_OPTIONS,
  IN_TUNNEL_CLOSED,
  IN_TUNNEL_CONFIGURE_STREAM_ERROR,
  IN_TUNNEL_CONFIGURE_UPDATE_STREAM_ERROR,
  IN_TUNNEL_ESTABLISHED,
  IN_TUNNEL_IN_OUT_STREAM_CLOSED,
  IN_TUNNEL_IN_OUT_STREAM_ERROR,
  IN_TUNNEL_IN_OUT_STREAM_ESTABLISHED,
  IN_TUNNEL_OUT_IN_STREAM_CLOSED,
  IN_TUNNEL_OUT_IN_STREAM_ERROR,
  IN_TUNNEL_OUT_IN_STREAM_ESTABLISHED,
  IN_TUNNEL_PASSWORD_MISMATCH,
  IN_TUNNEL_SERVER_LISTENING_ON,
  IN_TUNNEL_SERVER_TUNNELING,
  IN_TUNNEL_UPDATED,
  IN_TUNNEL_WINDOW_SIZE_UPDATED,
  Logs,
} from '../@log/index.js';
import type {
  TunnelId,
  TunnelInOutHeaderData,
  TunnelOutInErrorResponseHeaderData,
  TunnelOutInHeaderData,
  TunnelOutInTunnelResponseHeaderData,
  TunnelStreamId,
} from '../common.js';
import {
  INITIAL_WINDOW_SIZE,
  TUNNEL_HEADER_NAME,
  TUNNEL_PORT_DEFAULT,
  decodeTunnelHeader,
  encodeTunnelHeader,
} from '../common.js';
import {setupAutoWindowSize} from '../window-size.js';
import type {ListeningHost, Port} from '../x.js';

import type {RouteCandidate, Router} from './router/index.js';

const MAX_OUTSTANDING_PINGS = 5;

const HOST_DEFAULT = '';

export type TunnelServerOptions = {
  alias?: string;
  host?: ListeningHost;
  port?: Port;
  cert: string | Buffer;
  key: string | Buffer;
  password?: string;
};

export class TunnelServer {
  readonly server: HTTP2.Http2SecureServer;

  readonly alias: string | undefined;

  readonly password: string | undefined;

  private tunnelMap = new Map<TunnelId, Tunnel>();
  private sessionToTunnelIdMap = new Map<HTTP2.Http2Session, TunnelId>();

  constructor(
    readonly router: Router,
    {
      alias,
      host = HOST_DEFAULT,
      port = TUNNEL_PORT_DEFAULT,
      cert,
      key,
      password,
    }: TunnelServerOptions,
  ) {
    this.server = HTTP2.createSecureServer({
      settings: {
        initialWindowSize: INITIAL_WINDOW_SIZE,
      },
      cert,
      key,
      maxOutstandingPings: MAX_OUTSTANDING_PINGS,
    })
      .on('session', session => {
        setupAutoWindowSize(session, INITIAL_WINDOW_SIZE, windowSize => {
          const tunnelId = this.sessionToTunnelIdMap.get(session);

          if (tunnelId === undefined) {
            return;
          }

          Logs.debug(
            {
              type: 'in',
              tunnel: tunnelId,
            },
            IN_TUNNEL_WINDOW_SIZE_UPDATED(windowSize),
          );
        });
      })
      .on('stream', (stream, headers) => {
        const data = decodeTunnelHeader<TunnelOutInHeaderData>(
          headers[TUNNEL_HEADER_NAME] as string,
        );

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
        Logs.info('tunnel-server', IN_TUNNEL_SERVER_LISTENING_ON(host, port));
      });

    this.alias = alias;
    this.password = password;
  }

  async connect(
    upperContext: InLogContext,
    route: RouteCandidate,
    host: string,
    port: number,
  ): Promise<Duplex> {
    const tunnel = this.tunnelMap.get(route.tunnel);

    assert(tunnel);

    const {tunnelStream} = tunnel;

    const id = ++tunnel.lastStreamIdNumber as TunnelStreamId;

    const context: InLogContext = {
      ...upperContext,
      ...tunnel.context,
      stream: id,
    };

    Logs.info(
      context,
      IN_TUNNEL_SERVER_TUNNELING(host, port, tunnel.remoteAddress),
    );

    return new Promise((resolve, reject) => {
      tunnelStream.pushStream(
        {
          [TUNNEL_HEADER_NAME]: encodeTunnelHeader<TunnelInOutHeaderData>({
            type: 'in-out-stream',
            id,
            host,
            port,
          }),
        },
        (error, inOutStream) => {
          if (error) {
            reject(error);
            return;
          }

          Logs.debug(context, IN_TUNNEL_IN_OUT_STREAM_ESTABLISHED);

          inOutStream
            .on('close', () => {
              tunnel.connectionMap.delete(id);

              Logs.debug(context, IN_TUNNEL_IN_OUT_STREAM_CLOSED);
            })
            .on('error', error => {
              Logs.error(context, IN_TUNNEL_IN_OUT_STREAM_ERROR(error));
              Logs.debug(context, error);
            });

          tunnel.connectionMap.set(id, {
            context,
            resolve(outInStream) {
              if (!tunnel.connectionMap.has(id)) {
                outInStream.destroy();
                return;
              }

              outInStream
                .on('close', () => {
                  // Possibly redundant as pipelines() would close other
                  // pipelines if any from stream closes.
                  tunnel.connectionMap.delete(id);

                  Logs.debug(context, IN_TUNNEL_OUT_IN_STREAM_CLOSED);
                })
                .on('error', error => {
                  Logs.error(context, IN_TUNNEL_OUT_IN_STREAM_ERROR(error));
                  Logs.debug(context, error);
                });

              const stream = duplexer3(
                {bubbleErrors: false},
                inOutStream,
                outInStream,
              );

              resolve(stream);
            },
          });
        },
      );
    });
  }

  private handleTunnel(
    {
      alias,
      routeMatchOptions,
      password,
    }: TunnelOutInHeaderData & {type: 'tunnel'},
    stream: HTTP2.ServerHttp2Stream,
  ): void {
    const session = stream.session;

    assert(session);

    let id = this.sessionToTunnelIdMap.get(session);

    if (id === undefined) {
      if (password !== this.password) {
        Logs.error(
          'tunnel-server',
          IN_TUNNEL_PASSWORD_MISMATCH(session.socket!.remoteAddress!),
        );

        stream.respond(
          {
            ':status': 401,
            [TUNNEL_HEADER_NAME]:
              encodeTunnelHeader<TunnelOutInErrorResponseHeaderData>({
                error: 'password mismatch.',
              }),
          },
          {endStream: true},
        );
        session.close();
        return;
      }

      id = this.getNextTunnelId();

      const context: InLogContext = {
        type: 'in',
        tunnel: id,
        tunnelAlias: alias,
      };

      this.tunnelMap.set(id, {
        id,
        context,
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

      stream
        .on('close', () => {
          this.tunnelMap.delete(id!);
          this.sessionToTunnelIdMap.delete(session);
          this.router.unregister(id!);

          Logs.info(context, IN_TUNNEL_CLOSED);
        })
        .on('error', error => {
          Logs.error(context, IN_TUNNEL_CONFIGURE_STREAM_ERROR(error));
          Logs.debug(context, error);
        });

      stream.respond({
        ':status': 200,
        [TUNNEL_HEADER_NAME]:
          encodeTunnelHeader<TunnelOutInTunnelResponseHeaderData>({
            alias: this.alias,
          }),
      });

      Logs.info(context, IN_TUNNEL_ESTABLISHED);
      Logs.debug(
        context,
        IN_ROUTE_MATCH_OPTIONS,
        JSON.stringify(routeMatchOptions, undefined, 2),
      );
    } else {
      const tunnel = this.tunnelMap.get(id);

      assert(tunnel);

      const {context} = tunnel;

      this.router.update(id, routeMatchOptions);

      stream.on('error', error => {
        Logs.error(context, IN_TUNNEL_CONFIGURE_UPDATE_STREAM_ERROR(error));
        Logs.debug(context, error);
      });

      stream.respond({':status': 200}, {endStream: true});

      Logs.info(context, IN_TUNNEL_UPDATED);
      Logs.debug(
        context,
        IN_ROUTE_MATCH_OPTIONS,
        JSON.stringify(routeMatchOptions, undefined, 2),
      );
    }
  }

  private handleOutInStream(
    {id}: TunnelOutInHeaderData & {type: 'out-in-stream'},
    stream: HTTP2.ServerHttp2Stream,
  ): void {
    const {session} = stream;

    assert(session);

    const tunnelId = this.sessionToTunnelIdMap.get(session);

    if (tunnelId === undefined) {
      // Should not receive out-in-stream request for tunnel not configured.
      session.close();
      return;
    }

    const connection = this.tunnelMap.get(tunnelId)?.connectionMap.get(id);

    if (!connection) {
      return;
    }

    Logs.debug(connection.context, IN_TUNNEL_OUT_IN_STREAM_ESTABLISHED);

    connection.resolve(stream);

    stream.respond({':status': 200});
  }

  private lastTunnelIdNumber = 0;

  private getNextTunnelId(): TunnelId {
    return ++this.lastTunnelIdNumber as TunnelId;
  }
}

export type TunnelConnection = {
  context: InLogContext;
  resolve(outInStream: Readable): void;
};

export type Tunnel = {
  id: TunnelId;
  context: InLogContext;
  remoteAddress: string;
  tunnelStream: HTTP2.ServerHttp2Stream;
  connectionMap: Map<TunnelStreamId, TunnelConnection>;
  lastStreamIdNumber: number;
};
