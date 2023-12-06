import bytes from 'bytes';
import type * as x from 'x-value';

import type {RouteMatchOptions} from './router.js';
import {Port} from './x.js';

export const TUNNEL_PORT_DEFAULT = Port.nominalize(8443);

export const INITIAL_WINDOW_SIZE = bytes('4MB');

export type ConnectionId = x.Nominal<'connection id', number>;

export const TUNNEL_HEADER_NAME = 'x-tunnel';

export type TunnelId = x.Nominal<'tunnel id', number>;

export type TunnelStreamId = x.Nominal<'tunnel stream id', number>;

export type TunnelInOutHeaderData = {
  type: 'in-out-stream';
  id: TunnelStreamId;
  host: string;
  port: number;
};

export type TunnelOutInHeaderData =
  | {
      type: 'tunnel';
      alias: string | undefined;
      routeMatchOptions: RouteMatchOptions;
      password?: string;
    }
  | {
      type: 'out-in-stream';
      id: TunnelStreamId;
    };

export type TunnelOutInTunnelResponseHeaderData = {
  alias: string | undefined;
};

export type TunnelOutInErrorResponseHeaderData = {
  error: string;
};

export function encodeTunnelHeader<T>(data: T): string {
  return Buffer.from(JSON.stringify(data), 'utf8').toString('base64');
}

export function decodeTunnelHeader<T>(header: string): T {
  return JSON.parse(Buffer.from(header, 'base64').toString('utf8'));
}
