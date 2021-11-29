import {OutgoingHttpHeaders} from 'http';

export type InOutData =
  | InOutConnectData
  | InOutRequestData
  | InOutRouteData
  | InOutErrorData
  | StreamChunkData
  | StreamEndData;

export interface InOutConnectData {
  type: 'connect';
  options: InOutConnectOptions;
}

export interface InOutRequestData {
  type: 'request';
  options: InOutRequestOptions;
}

export interface InOutRouteData {
  type: 'route';
  host: string;
}

export interface InOutErrorData {
  type: 'error';
  message: string;
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

export type OutInData =
  | OutInInitializeData
  | OutInDirectData
  | OutInRouteResultData
  | OutInConnectedData
  | OutInResponseData
  | StreamChunkData
  | StreamEndData;

export interface OutInInitializeData {
  type: 'initialize';
  password?: string;
}

export interface OutInConnectedData {
  type: 'connected';
}

export interface OutInDirectData {
  type: 'direct';
}

export interface OutInRouteResultData {
  type: 'route-result';
  route: InRoute;
}

export interface OutInResponseData {
  type: 'response';
  status: number;
  headers?: OutgoingHttpHeaders;
}

export type InRoute = 'direct' | 'proxy';

export interface StreamChunkData {
  type: 'stream-chunk';
  chunk: Buffer;
}

export interface StreamEndData {
  type: 'stream-end';
}
