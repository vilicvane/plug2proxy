import type {Readable, Writable} from 'stream';
import {pipeline} from 'stream/promises';

import {getErrorCode} from './miscellaneous.js';
import duplexer3 from 'duplexer3';

export async function pipelines(
  pipelines: [from: Readable, to: Writable][],
): Promise<void> {
  const fromStreams = pipelines.map(([from]) => from);

  const onFromClose = function (this: Readable): void {
    for (const [from, to] of pipelines) {
      if (from !== this) {
        from.destroy();
        to.destroy();
      }
    }
  };

  for (const from of fromStreams) {
    from.on('close', onFromClose);
  }

  try {
    await Promise.all(pipelines.map(([from, to]) => pipeline(from, to)));
  } catch (error) {
    for (const [from, to] of pipelines) {
      from.destroy();
      to.destroy();
    }

    switch (getErrorCode(error)) {
      case 'ERR_STREAM_PREMATURE_CLOSE':
        break;
      default:
        throw error;
    }
  } finally {
    for (const from of fromStreams) {
      from.off('close', onFromClose);
    }
  }
}

export function duplexify(writable: Writable, readable: Readable) {
  const duplex = duplexer3(writable, readable);

  duplex.on('close', () => {
    writable.destroy();
    readable.destroy();
  });

  writable.on('close', () => readable.destroy());
  readable.on('close', () => writable.destroy());

  return duplex;
}
