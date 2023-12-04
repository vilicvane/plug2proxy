import type EventEmitter from 'events';
import type {Readable, Writable} from 'stream';

export type ErrorWhileEventEmitter = [
  eventEmitter: EventEmitter,
  onError: (error: unknown) => void,
  dispose: () => void,
];

export function errorWhile<T>(
  targetPromise: Promise<T>,
  targetPromiseOnError: (error: unknown) => void,
  eventEmitterEntries: ErrorWhileEventEmitter[],
): Promise<T>;
export function errorWhile<T>(
  targetPromise: Promise<T>,
  targetPromiseOnError: (error: unknown) => void,
  targetDispose: () => void,
  eventEmitterEntries: ErrorWhileEventEmitter[],
): Promise<T>;
export function errorWhile<T>(
  targetPromise: Promise<T>,
  targetPromiseOnError: (error: unknown) => void,
  ...args: [ErrorWhileEventEmitter[]] | [() => void, ErrorWhileEventEmitter[]]
): Promise<T> {
  const [targetDispose, eventEmitterEntries] =
    args.length === 1 ? [() => {}, ...args] : args;

  let errorListenersRemover!: () => void;

  const errorPromise = new Promise<never>((_resolve, reject) => {
    for (const [eventEmitter, onError] of eventEmitterEntries) {
      eventEmitter.on('error', reject);
      eventEmitter.on('error', onError);
    }

    errorListenersRemover = () => {
      for (const [eventEmitter, onError] of eventEmitterEntries) {
        eventEmitter.off('error', reject);
        eventEmitter.off('error', onError);
      }
    };
  });

  return Promise.race([
    targetPromise.catch(error => {
      targetPromiseOnError(error);
      throw error;
    }),
    errorPromise,
  ])
    .catch(error => {
      targetDispose();

      for (const [, , dispose] of eventEmitterEntries) {
        dispose();
      }

      throw error;
    })
    .finally(errorListenersRemover);
}

export function streamErrorWhileEntry(
  stream: Readable | Writable,
  onError: (error: unknown) => void,
): ErrorWhileEventEmitter {
  return [stream, onError, () => stream.destroy()];
}
