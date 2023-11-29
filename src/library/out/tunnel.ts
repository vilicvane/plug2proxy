import {once} from 'events';
import * as HTTP2 from 'http2';
import * as Net from 'net';

import * as x from 'x-value';

import type {TunnelInOutHeaderData, TunnelOutInHeaderData} from '../common.js';
import {TUNNEL_HEADER_NAME} from '../common.js';
import {RouteMatchOptions} from '../router.js';

export const TunnelConfig = x.object({
  routeMatchOptions: RouteMatchOptions,
});

export type TunnelConfig = x.TypeOf<typeof TunnelConfig>;

export const TunnelOptions = x.object({
  /**
   * 代理入口服务器，如 "https://example.com:8443"。
   */
  authority: x.string,
  rejectUnauthorized: x.boolean.optional(),
  config: TunnelConfig.optional(),
});

export type TunnelOptions = x.TypeOf<typeof TunnelOptions>;

export class Tunnel {
  readonly authority: string;
  readonly rejectUnauthorized: boolean;

  config: TunnelConfig | undefined;

  private client: HTTP2.ClientHttp2Session | undefined;

  constructor({authority, rejectUnauthorized = true, config}: TunnelOptions) {
    this.authority = authority;
    this.rejectUnauthorized = rejectUnauthorized;
    this.config = config;

    this.connect();
  }

  configure(config: TunnelConfig): void {
    this.config = config;
    this._configure();
  }

  private connect(): void {
    const client = HTTP2.connect(this.authority, {
      rejectUnauthorized: this.rejectUnauthorized,
    }).on('stream', (stream, headers) => {
      const data = JSON.parse(
        headers[TUNNEL_HEADER_NAME] as string,
      ) as TunnelInOutHeaderData;

      switch (data.type) {
        case 'in-out-stream':
          void this.handleInOutStream(data, stream, client);
          break;
      }
    });

    this.client = client;

    this._configure();
  }

  private _configure(): void {
    const {client, config} = this;

    if (!client || !config) {
      return;
    }

    client.request(
      {
        [TUNNEL_HEADER_NAME]: JSON.stringify({
          type: 'tunnel',
          ...config,
        } satisfies TunnelOutInHeaderData),
      },
      {endStream: true},
    );
  }

  private async handleInOutStream(
    {id, host, port}: TunnelInOutHeaderData,
    inOutStream: HTTP2.ClientHttp2Stream,
    client: HTTP2.ClientHttp2Session,
  ): Promise<void> {
    const outStream = Net.connect(port, host);

    await once(outStream, 'connect');

    // inOutStream.on('data', data => console.log('tunnel in-out stream', data));

    inOutStream.pipe(outStream);

    const outInStream = client.request(
      {
        [TUNNEL_HEADER_NAME]: JSON.stringify({
          type: 'out-in-stream',
          id,
        } satisfies TunnelOutInHeaderData),
      },
      {
        endStream: false,
      },
    );

    outStream.pipe(outInStream);
  }
}
