import type {Readable, Writable} from 'stream';
import {pipeline} from 'stream/promises';

import {getErrorCode} from './miscellaneous.js';

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
