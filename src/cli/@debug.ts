import EventEmitter from 'events';

const error_emitter_symbol = Symbol('error emitter');

export function setupDebug(): void {
  process.on('warning', warning => console.warn(warning.stack));

  const originalEmit = EventEmitter.prototype.emit;

  EventEmitter.prototype.emit = function emit(type, ...args) {
    if (type === 'error') {
      const error = args[0];

      if (error instanceof Error) {
        (error as any)[error_emitter_symbol] = this;
      }
    }

    return originalEmit.apply(this, [type, ...args]);
  };
}
