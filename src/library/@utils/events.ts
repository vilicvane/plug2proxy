import type EventEmitter from 'events';

export function handleErrorWhile<T>(
  promise: Promise<T>,
  eventEmitters: EventEmitter[],
): Promise<T> {
  let errorListenersRemover!: () => void;

  const errorPromise = new Promise<never>((_resolve, reject) => {
    for (const eventEmitter of eventEmitters) {
      eventEmitter.on('error', reject);
    }

    errorListenersRemover = () => {
      for (const eventEmitter of eventEmitters) {
        eventEmitter.off('error', reject);
      }
    };
  });

  return Promise.race([promise, errorPromise]).finally(errorListenersRemover);
}
