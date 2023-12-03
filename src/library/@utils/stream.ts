import type {Readable, Writable} from 'stream';
import {pipeline} from 'stream/promises';

import {getErrorCode} from './miscellaneous.js';

export async function pipelines(
  pipelines: [from: Readable, to: Writable][],
): Promise<void> {
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
  }
}
