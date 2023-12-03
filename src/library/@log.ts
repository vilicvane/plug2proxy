import Chalk from 'chalk';
import type {Debugger} from 'debug';
import Debug from 'debug';

import type {ConnectionId, TunnelId, TunnelStreamId} from './common.js';
import type {Out} from './out/index.js';

export type InConnectLogContext = {
  type: 'in:connect';
  id: ConnectionId;
  host: string;
  port: number;
};

export type InRequestLogContext = {
  type: 'in:request';
  id: ConnectionId;
  url: string;
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

export type InTunnelServerLogContext = {
  type: 'in:tunnel-server';
};

export type InRouterLogContext = {
  type: 'in:router';
};

export type InGeoLite2LogContext = {
  type: 'in:geolite2';
};

export type InWebLogContext = {
  type: 'in:web';
};

export type OutTunnelLogContext = {
  type: 'out:tunnel';
  id: Out.TunnelId;
};

export type OutTunnelStreamLogContext = {
  type: 'out:tunnel-stream';
  stream: TunnelStreamId;
};

type LogContext =
  | InConnectLogContext
  | InRequestLogContext
  | InTunnelConnectLogContext
  | InTunnelLogContext
  | InTunnelServerLogContext
  | InRouterLogContext
  | InGeoLite2LogContext
  | InWebLogContext
  | OutTunnelLogContext
  | OutTunnelStreamLogContext;

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_COLORS: Record<
  Exclude<string, 'debug'>,
  (text: string) => string
> = {
  info: text => text,
  warn: Chalk.yellow,
  error: Chalk.red,
};

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
          console[level](
            ...args.map(arg =>
              typeof arg === 'string' ? LEVEL_COLORS[level](arg) : arg,
            ),
          );

  return function log(context, ...args) {
    switch (context.type) {
      case 'in:connect':
        args = [`[${CONNECTION(context.id)}]`, ...args];
        break;
      case 'in:tunnel-connect':
        args = [
          `[${CONNECTION(context.connection)}${IN_TUNNEL(context.tunnel)}${
            context.stream !== undefined
              ? `${TUNNEL_STREAM(context.stream)}`
              : ''
          }]`,
          ...args,
        ];
        break;
      case 'in:tunnel':
        args = [`[${IN_TUNNEL(context.id)}]`, ...args];
        break;
      case 'out:tunnel':
        args = [`[${OUT_TUNNEL(context.id)}]`, ...args];
        break;
      case 'out:tunnel-stream':
        args = [`[${TUNNEL_STREAM(context.stream)}]`, ...args];
        break;
      default:
        args = [`[${context.type.replace(/^(?:in|out):/, '')}]`, ...args];
        break;
    }

    write(context.type, args);
  };
}

function CONNECTION(id: ConnectionId): string {
  return `#${id}`;
}

function IN_TUNNEL(id: TunnelId): string {
  return `>${id}`;
}

function OUT_TUNNEL(id: Out.TunnelId): string {
  return `<${id}`;
}

function TUNNEL_STREAM(id: TunnelStreamId): string {
  return `:${id}`;
}
