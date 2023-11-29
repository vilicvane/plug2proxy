import Chalk from 'chalk';

import type {ConnectionId, TunnelId, TunnelStreamId} from './common.js';

export type LogContext =
  | {
      type: 'connect';
      id: ConnectionId;

      hostname: string;
    }
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
    if (args.length === 0) {
      switch (context.type) {
        case 'connect':
          args = [`${Chalk.cyan('connect')} ${context.hostname}`];
          break;
      }
    }

    switch (context.type) {
      case 'connect':
        args = [`[${context.id}]`, ...args];
        break;
      default:
        args = [`[${context.type}]`, ...args];
        break;
    }

    // eslint-disable-next-line no-console
    console[level](...args);
  };
}
