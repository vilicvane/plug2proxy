import {OutgoingHttpHeaders} from 'http';

import {InRoute} from './types';

export type InOutPacket =
  | InOutPingPacket
  | InOutConnectPacket
  | InOutRequestPacket
  | InOutRoutePacket
  | InOutReturnPacket
  | InOutErrorPacket
  | StreamPacket;

export interface InOutPingPacket {
  type: 'ping';
  timestamp: number;
  span?: number;
}

export interface InOutConnectPacket {
  type: 'connect';
  options: InOutConnectOptions;
}

export interface InOutRequestPacket {
  type: 'request';
  options: InOutRequestOptions;
}

export interface InOutRoutePacket {
  type: 'route';
  host: string;
}

export interface InOutReturnPacket {
  type: 'return';
}

export interface InOutErrorPacket {
  type: 'error';
  code: string;
}

export interface InOutConnectOptions {
  host: string;
  port: number;
}

export interface InOutRequestOptions {
  method: string;
  url: string;
  headers: OutgoingHttpHeaders;
}

export type OutInPacket =
  | OutInPongPacket
  | OutInReadyPacket
  | OutInConnectionEstablishedPacket
  | OutInConnectionDirectPacket
  | OutInConnectionErrorPacket
  | OutInRequestResponsePacket
  | OutInRouteResultPacket
  | StreamPacket;

export interface OutInPongPacket {
  type: 'pong';
  timestamp: number;
}

export interface OutInReadyPacket {
  type: 'ready';
  id?: string;
  password?: string;
}

export interface OutInConnectionEstablishedPacket {
  type: 'connection-established';
}

export interface OutInConnectionDirectPacket {
  type: 'connection-direct';
}

export interface OutInConnectionErrorPacket {
  type: 'connection-error';
}

export interface OutInRequestResponsePacket {
  type: 'request-response';
  status: number;
  headers?: OutgoingHttpHeaders;
}

export interface OutInRouteResultPacket {
  type: 'route-result';
  route: InRoute;
}

export type StreamPacket = StreamChunkPacket | StreamEndPacket;

export interface StreamChunkPacket {
  type: 'stream-chunk';
  chunk: Buffer;
}

export interface StreamEndPacket {
  type: 'stream-end';
}
