import Chalk from 'chalk';
import type {Debugger} from 'debug';
import Debug from 'debug';

import type {ConnectionId, TunnelId, TunnelStreamId} from './common.js';

export type InConnectLogContext = {
  type: 'in:connect';
  id: ConnectionId;
  host: string;
  port: number;
};

export type InTunnelConnectLogContext = {
  type: 'in:tunnel-connect';
  connection: ConnectionId;
  tunnel: TunnelId;
  stream?: TunnelStreamId;
};

export type InTunnelLogContext = {
  type: 'in:tunnel';
  id: TunnelId;
};

export type OutTunnelLogContext = {
  type: 'out:tunnel';
};

export type OutTunnelStreamLogContext = {
  type: 'out:tunnel-stream';
  stream: TunnelStreamId;
};

export type LogContext =
  | InConnectLogContext
  | InTunnelConnectLogContext
  | InTunnelLogContext
  | OutTunnelLogContext
  | OutTunnelStreamLogContext
  | {
      type: 'in:tunnel-server';
    }
  | {
      type: 'in:router';
    }
  | {
      type: 'in:geolite2';
    };

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

export namespace Logs {
  export const debug = createLogger('debug');

  export const info = createLogger('info');

  export const warn = createLogger('warn');

  export const error = createLogger('error');
}

function createLogger<TLevel extends LogLevel>(
  level: TLevel,
): (context: LogContext, ...args: unknown[]) => void {
  const write: (type: string, args: unknown[]) => void =
    level === 'debug'
      ? (() => {
          const debugMap = new Map<string, Debugger>();

          return (type, args) => {
            const namespace = `plug2proxy:${type}`;

            let debug = debugMap.get(namespace);

            if (!debug) {
              debug = Debug(namespace);
              debugMap.set(namespace, debug);
            }

            (debug as any)(...args);
          };
        })()
      : (_type, args) =>
          // eslint-disable-next-line no-console
          console[level](...args);

  return function log(context, ...args) {
    switch (context.type) {
      case 'in:connect':
        args = [`[${CONNECTION(context.id)}]`, ...args];
        break;
      case 'in:tunnel-connect':
        args = [
          `[${CONNECTION(context.connection)}${TUNNEL(context.tunnel)}${
            context.stream !== undefined
              ? `${TUNNEL_STREAM(context.stream)}`
              : ''
          }]`,
          ...args,
        ];
        break;
      case 'in:tunnel':
        args = [`[${TUNNEL(context.id)}]`, ...args];
        break;
      case 'out:tunnel-stream':
        args = [`[${TUNNEL_STREAM(context.stream)}]`, ...args];
        break;
      default:
        args = [`[${context.type}]`, ...args];
        break;
    }

    write(context.type, args);
  };
}

function CONNECTION(id: ConnectionId): string {
  return `#${id}`;
}

function TUNNEL(id: TunnelId): string {
  return `>${id}`;
}

function TUNNEL_STREAM(id: TunnelStreamId): string {
  return `:${id}`;
}
