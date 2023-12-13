import * as HTTP2 from 'http2';
import * as Net from 'net';

import {setupAutoWindowSize} from 'http2-auto-window-size';
import type * as x from 'x-value';

import type {OutLogContext} from '../@log/index.js';
import {
  Logs,
  OUT_CONNECTING,
  OUT_ERROR_CONFIGURING_TUNNEL,
  OUT_ERROR_PIPING_TUNNEL_STREAM_FROM_TO_PROXY_STREAM,
  OUT_RECEIVED_IN_OUT_STREAM,
  OUT_RECONNECT_IN,
  OUT_TUNNEL_CLOSED,
  OUT_TUNNEL_ERROR,
  OUT_TUNNEL_ESTABLISHED,
  OUT_TUNNEL_OUT_IN_STREAM_ESTABLISHED,
  OUT_TUNNEL_STREAM_CLOSED,
  OUT_TUNNEL_WINDOW_SIZE_UPDATED,
} from '../@log/index.js';
import {generateRandomAuthoritySegment, pipelines} from '../@utils/index.js';
import type {
  TunnelInOutHeaderData,
  TunnelOutInErrorResponseHeaderData,
  TunnelOutInHeaderData,
  TunnelOutInTunnelResponseHeaderData,
} from '../common.js';
import {
  INITIAL_WINDOW_SIZE,
  TUNNEL_HEADER_NAME,
  TUNNEL_PORT_DEFAULT,
  decodeTunnelHeader,
  encodeTunnelHeader,
} from '../common.js';
import type {
  RouteMatchIncludeRule,
  RouteMatchOptions,
  RouteMatchRule,
} from '../router.js';

const RECONNECT_DELAYS = [1000, 1000, 1000, 5000, 10_000, 30_000, 60_000];

function RECONNECT_DELAY(attempts: number): number {
  return RECONNECT_DELAYS[Math.min(attempts, RECONNECT_DELAYS.length - 1)];
}

const ROUTE_MATCH_INCLUDE_DEFAULT: RouteMatchIncludeRule[] = [{type: 'all'}];

const ROUTE_MATCH_EXCLUDE_DEFAULT: RouteMatchRule[] = [
  {type: 'ip', match: 'private'},
];

export type TunnelOptions = {
  alias?: string;
  host: string;
  port?: number;
  password?: string;
  rejectUnauthorized?: boolean;
  match?: RouteMatchOptions;
};

export type TunnelId = x.Nominal<'tunnel id', number>;

export class Tunnel {
  readonly context: OutLogContext;

  readonly alias: string | undefined;

  readonly authority: string;

  readonly password: string | undefined;

  readonly rejectUnauthorized: boolean;

  private routeMatchOptions: RouteMatchOptions;

  private session: HTTP2.ClientHttp2Session | undefined;

  private sessionConfigured = false;

  private continuousAttempts = 0;

  private reconnectTimer: NodeJS.Timeout | undefined;

  constructor(
    readonly id: TunnelId,
    {
      host,
      port = TUNNEL_PORT_DEFAULT,
      password,
      rejectUnauthorized = true,
      match: routeMatchOptions = {},
      alias,
    }: TunnelOptions,
  ) {
    this.context = {
      type: 'out',
      tunnel: id,
    };

    this.alias = alias;

    this.authority = `https://${host.replace(
      '#',
      generateRandomAuthoritySegment(),
    )}:${port}`;

    this.password = password;

    this.rejectUnauthorized = rejectUnauthorized;

    this.routeMatchOptions = {
      include: ROUTE_MATCH_INCLUDE_DEFAULT,
      exclude: ROUTE_MATCH_EXCLUDE_DEFAULT,
      ...routeMatchOptions,
    };

    this.connect();
  }

  configure(routeMatchOptions: RouteMatchOptions): void {
    this.routeMatchOptions = routeMatchOptions;
    this._configure();
  }

  private connect(): void {
    const {context} = this;

    this.continuousAttempts++;

    Logs.info(context, OUT_CONNECTING(this.authority));

    const session = HTTP2.connect(this.authority, {
      rejectUnauthorized: this.rejectUnauthorized,
      settings: {
        initialWindowSize: INITIAL_WINDOW_SIZE,
      },
    })
      .on('connect', session => {
        setupAutoWindowSize(session, {
          initialWindowSize: INITIAL_WINDOW_SIZE,
          onSetLocalWindowSize: windowSize => {
            Logs.debug(
              this.context,
              OUT_TUNNEL_WINDOW_SIZE_UPDATED(windowSize),
            );
          },
        });

        this._configure();
      })
      .on('stream', (stream, headers) => {
        const data = decodeTunnelHeader<TunnelInOutHeaderData>(
          headers[TUNNEL_HEADER_NAME] as string,
        )!;

        switch (data.type) {
          case 'in-out-stream':
            void this.handleInOutStream(data, stream, session);
            break;
        }
      })
      .on('close', () => {
        Logs.info(context, OUT_TUNNEL_CLOSED);
        this.scheduleReconnect();
      })
      .on('error', error => {
        Logs.error(context, OUT_TUNNEL_ERROR(error));
        Logs.debug(context, error);
      });

    this.session = session;
    this.sessionConfigured = false;
  }

  private scheduleReconnect(): void {
    clearTimeout(this.reconnectTimer);

    const delay = RECONNECT_DELAY(this.continuousAttempts);

    Logs.info(this.context, OUT_RECONNECT_IN(delay));

    this.reconnectTimer = setTimeout(() => this.connect(), delay);
  }

  private _configure(): void {
    const {session} = this;

    if (!session) {
      return;
    }

    const {routeMatchOptions, sessionConfigured} = this;

    if (!sessionConfigured) {
      this.sessionConfigured = true;
    }

    const stream = session.request(
      {
        [TUNNEL_HEADER_NAME]: encodeTunnelHeader<TunnelOutInHeaderData>({
          type: 'tunnel',
          alias: this.alias,
          routeMatchOptions,
          password: sessionConfigured ? undefined : this.password,
        }),
      },
      {endStream: true},
    );

    stream
      .on('response', headers => {
        if (sessionConfigured) {
          return;
        }

        const status = headers[':status'];
        const tunnelHeader = headers[TUNNEL_HEADER_NAME] as string;

        if (status === 200) {
          this.continuousAttempts = 0;

          const {alias} =
            decodeTunnelHeader<TunnelOutInTunnelResponseHeaderData>(
              tunnelHeader,
            )!;

          this.context.tunnelAlias = alias;

          Logs.info(this.context, OUT_TUNNEL_ESTABLISHED);
        } else {
          const {error} =
            decodeTunnelHeader<TunnelOutInErrorResponseHeaderData>(
              tunnelHeader,
            )!;

          Logs.error(this.context, OUT_ERROR_CONFIGURING_TUNNEL(status, error));
        }
      })
      .on('close', () => {
        if (sessionConfigured) {
          return;
        }

        // Session 'close' event sometimes not emitted, don't know why.
        this.scheduleReconnect();
      })
      .on('error', error => {
        Logs.debug(this.context, error);
      });
  }

  private async handleInOutStream(
    {id, host, port}: TunnelInOutHeaderData,
    inOutStream: HTTP2.ClientHttp2Stream,
    session: HTTP2.ClientHttp2Session,
  ): Promise<void> {
    const context: OutLogContext = {
      ...this.context,
      stream: id,
      host: `${host}:${port}`,
    };

    Object.setPrototypeOf(context, this.context);

    Logs.info(context, OUT_RECEIVED_IN_OUT_STREAM(host, port));

    const proxyStream = Net.connect(port, host);

    const outInStream = session.request(
      {
        [TUNNEL_HEADER_NAME]: encodeTunnelHeader<TunnelOutInHeaderData>({
          type: 'out-in-stream',
          id,
        }),
      },
      {endStream: false},
    );

    outInStream.on('response', headers => {
      if (headers[':status'] === 200) {
        Logs.info(context, OUT_TUNNEL_OUT_IN_STREAM_ESTABLISHED);
      }
    });

    try {
      await pipelines([
        [inOutStream, proxyStream],
        [proxyStream, outInStream],
      ]);

      Logs.info(context, OUT_TUNNEL_STREAM_CLOSED);
    } catch (error) {
      Logs.error(
        context,
        OUT_ERROR_PIPING_TUNNEL_STREAM_FROM_TO_PROXY_STREAM(error),
      );
      Logs.debug(context, error);
    }
  }
}
