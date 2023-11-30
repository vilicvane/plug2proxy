import Chalk from 'chalk';

import type {ConnectionId, TunnelId, TunnelStreamId} from './common.js';

export type ConnectLogContext = {
  type: 'connect';
  id: ConnectionId;
  host: string;
  port: number;
};

export type TunnelConnectLogContext = {
  type: 'tunnel-connect';
  connection: ConnectionId;
  tunnel: TunnelId;
  stream?: TunnelStreamId;
};

export type TunnelOutInLogContext = {
  type: 'tunnel-out-in';
  stream: TunnelStreamId;
  host: string;
  port: number;
};

export type LogContext =
  | ConnectLogContext
  | TunnelConnectLogContext
  | TunnelOutInLogContext
  | {
      type: 'tunnel-server';
    }
  | {
      type: 'router';
    }
  | {
      type: 'geolite2';
    };

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export namespace Logs {
  export const debug = createLogger('debug');

  export const info = createLogger('info');

  export const warn = createLogger('warn');

  export const error = createLogger('error');
}

function createLogger<TLevel extends LogLevel>(level: TLevel) {
  return function log(context: LogContext, ...args: unknown[]) {
    switch (context.type) {
      case 'connect':
        args = [`[${context.id}]`, ...args];
        break;
      case 'tunnel-connect':
        args = [
          `[${context.connection}...${context.tunnel}]${
            context.stream !== undefined ? `(${context.stream})` : ''
          }`,
          ...args,
        ];
        break;
      case 'tunnel-out-in':
        args = [`(${context.stream})`, ...args];
        break;
      default:
        args = [`${context.type}:`, ...args];
        break;
    }

    // eslint-disable-next-line no-console
    console[level](...args);
  };
}
