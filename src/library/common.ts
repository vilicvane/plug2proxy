import type * as x from 'x-value';

import type {RouteMatchOptions} from './router.js';

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
      routeMatchOptions: RouteMatchOptions;
    }
  | {
      type: 'out-in-stream';
      id: TunnelStreamId;
    };
