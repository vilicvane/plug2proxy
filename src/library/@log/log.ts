import Chalk from 'chalk';

import type {ConnectionId, TunnelId, TunnelStreamId} from '../common.js';
import type {Out} from '../out/index.js';

const DEBUG_ENABLED = process.env.DEBUG?.includes('plug2proxy');

export type InLogContext = {
  type: 'in';
  method?: 'connect' | 'request';
  connection?: ConnectionId;
  tunnel?: TunnelId;
  stream?: TunnelStreamId;
  hostname?: string;
};

export type OutLogContext = {
  type: 'out';
  tunnel?: Out.TunnelId | string;
  stream?: TunnelStreamId;
  hostname?: string;
};

type LogContext =
  | InLogContext
  | OutLogContext
  | 'proxy'
  | 'tunnel-server'
  | 'router'
  | 'geolite2'
  | 'web';

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_COLORS: Record<LogLevel, (text: string) => string> = {
  debug: Chalk.dim,
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
  const write: (args: unknown[]) => void =
    level !== 'debug' || DEBUG_ENABLED
      ? args =>
          // eslint-disable-next-line no-console
          console[level](
            ...args.map(arg =>
              typeof arg === 'string' ? LEVEL_COLORS[level](arg) : arg,
            ),
          )
      : () => {};

  return function log(context, ...args) {
    let type: string;
    let prefix = '';

    if (typeof context === 'object') {
      type = context.type;

      switch (context.type) {
        case 'in':
          if (context.connection !== undefined) {
            prefix += CONNECTION(context.connection);
          }

          if (context.tunnel !== undefined) {
            prefix += IN_TUNNEL(context.tunnel);
          }

          if (context.stream !== undefined) {
            prefix += TUNNEL_STREAM(context.stream);
          }

          if (context.hostname !== undefined) {
            prefix += ` ${context.hostname}`;
          }

          break;
        case 'out':
          if (context.tunnel !== undefined) {
            prefix += OUT_TUNNEL(context.tunnel);
          }

          if (context.stream !== undefined) {
            prefix += TUNNEL_STREAM(context.stream);
          }

          if (context.hostname !== undefined) {
            prefix += ` ${context.hostname}`;
          }

          break;
      }

      if (prefix) {
        prefix = `[${prefix}]`;
      }
    } else {
      type = context;
      prefix = `[${type}]`;
    }

    write([prefix, ...args]);
  };
}

function CONNECTION(id: ConnectionId): string {
  return `#${id}`;
}

function IN_TUNNEL(id: TunnelId): string {
  return `>${id}`;
}

function OUT_TUNNEL(idOrAlias: Out.TunnelId | string): string {
  return `<${idOrAlias}`;
}

function TUNNEL_STREAM(id: TunnelStreamId): string {
  return `:${id}`;
}
