import * as HTTP2 from 'http2';

import bytes from 'bytes';
import * as x from 'x-value';
import * as xn from 'x-value/node';

import type {TunnelOutInHeaderData} from '../common.js';
import type {RouteMatchOptions} from '../router.js';
import {IPPattern, Port} from '../x.js';

import type {Router} from './router/index.js';

const HOST_DEFAULT = '';
const PORT_DEFAULT = Port.nominalize(8443);

const WINDOW_SIZE = bytes('32MB');

export const TunnelOptions = x.object({
  host: x.union([IPPattern, x.literal('')]).optional(),
  port: Port.optional(),
  cert: x.union([x.string, xn.Buffer]).optional(),
  key: x.union([x.string, xn.Buffer]).optional(),
  password: x.string.optional(),
});

export type TunnelOptions = x.TypeOf<typeof TunnelOptions>;

export class Tunnel {
  readonly server: HTTP2.Http2SecureServer;

  private tunnelStreamToCandidateMap = new Map<
    HTTP2.ServerHttp2Stream,
    TunnelCandidate
  >();

  constructor(
    readonly router: Router,
    {
      host = HOST_DEFAULT,
      port = PORT_DEFAULT,
      cert,
      key,
      password,
    }: TunnelOptions,
  ) {
    this.server = HTTP2.createSecureServer({
      settings: {
        initialWindowSize: WINDOW_SIZE,
      },
      cert,
      key,
    })
      .on('session', session => {
        session.setLocalWindowSize(WINDOW_SIZE); // necessary?
      })
      .on('stream', (stream, headers) => {
        const data = JSON.parse(
          headers['x-tunnel'] as string,
        ) as TunnelOutInHeaderData;

        switch (data.type) {
          case 'tunnel':
            this.handleTunnelRequest(data, stream);
            break;
          case 'out-in-stream':
            this.handleOutInRequest(data, stream);
            break;
        }
      });
  }

  private handleTunnelRequest(
    {routeMatchOptions}: TunnelOutInHeaderData & {type: 'tunnel'},
    stream: HTTP2.ServerHttp2Stream,
  ): void {
    const candidate: TunnelCandidate = {
      id: this.getNextTunnelCandidateId(),
      stream,
      routeMatchOptions,
    };

    this.tunnelStreamToCandidateMap.set(stream, candidate);

    stream.respond({':status': 200}, {endStream: true});
  }

  private handleOutInRequest(
    {id}: TunnelOutInHeaderData & {type: 'out-in-stream'},
    stream: HTTP2.ServerHttp2Stream,
  ): void {}

  private lastTunnelCandidateIdNumber = 0;

  private getNextTunnelCandidateId(): TunnelCandidateId;
  private getNextTunnelCandidateId(): string {
    return (++this.lastTunnelCandidateIdNumber).toString();
  }
}

export type TunnelCandidateId = x.Nominal<string, 'tunnel candidate id'>;

export type TunnelCandidate = {
  id: TunnelCandidateId;
  stream: HTTP2.ServerHttp2Stream;
  routeMatchOptions: RouteMatchOptions;
};
