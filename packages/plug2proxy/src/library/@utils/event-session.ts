import {EventEmitter} from 'events';

import {isTupleElementTypeOf} from './miscellaneous';

export class EventSession<T extends EventEmitter = EventEmitter> {
  private disposers: (() => void)[] = [];

  private _ended = false;

  constructor(
    private _emitter?: T,
    private _root?: EventSession,
    private endOnEventNames?: string[],
  ) {
    if (endOnEventNames) {
      this.endOn(endOnEventNames);
    }
  }

  get ended(): boolean {
    return this._ended;
  }

  get emitter(): T {
    let emitter = this._emitter;

    if (!emitter) {
      throw new Error('Emitter is not specified');
    }

    return emitter;
  }

  get root(): EventSession {
    return this._root ?? this;
  }

  ref<T extends EventEmitter>(emitter: T): EventSession<T> {
    this.assertNotEnded();

    let subSession = new EventSession(emitter, this.root, this.endOnEventNames);

    this.disposers.push(() => subSession.end());

    return subSession;
  }

  on(eventNames: string | string[], listener: (...args: any) => void): this {
    let emitter = this.emitter;

    this.assertNotEnded();

    if (typeof eventNames === 'string') {
      eventNames = [eventNames];
    }

    for (let eventName of eventNames) {
      emitter.on(eventName, listener);
    }

    this.disposers.push(() => {
      for (let eventName of eventNames) {
        emitter.off(eventName, listener);
      }
    });

    return this;
  }

  /**
   * @param eventNames If multiple event names provided, only one of them will
   * be triggered for only once at most.
   */
  once(eventNames: string | string[], listener: (...args: any) => void): this {
    let emitter = this.emitter;

    this.assertNotEnded();

    if (typeof eventNames === 'string') {
      eventNames = [eventNames];
    }

    for (let eventName of eventNames) {
      emitter.once(eventName, listener);
      emitter.once(eventName, off);
    }

    this.disposers.push(off);

    return this;

    function off(): void {
      for (let eventName of eventNames) {
        emitter.off(eventName, listener);
        emitter.off(eventName, off);
      }
    }
  }

  off(eventNames: string | string[], listener: (...args: any) => void): this {
    let emitter = this.emitter;

    this.assertNotEnded();

    if (typeof eventNames === 'string') {
      eventNames = [eventNames];
    }

    for (let eventName of eventNames) {
      emitter.off(eventName, listener);
    }

    return this;
  }

  end(): void {
    let root = this._root;

    if (root) {
      root.end();
      return;
    }

    this._ended = true;

    for (let disposer of this.disposers) {
      disposer();
    }

    this.disposers.splice(0);
  }

  endOn(eventNames: string | string[], listener?: () => boolean | void): this {
    this.on(eventNames, () => {
      if (listener?.() === false) {
        return;
      }

      this.end();
    });

    return this;
  }

  private assertNotEnded(): void {
    if (this.ended) {
      throw new Error('This event session has already been ended');
    }
  }
}

export function refEventEmitter<T extends EventEmitter>(
  emitter: T,
  endOnEventNames?: string | string[],
): EventSession<T>;
export function refEventEmitter<T extends EventEmitter, TReturn>(
  emitter: T,
  endOnEventNames: string | string[],
  callback: (session: EventSession<T>) => TReturn,
): TReturn;
export function refEventEmitter<T extends EventEmitter, TReturn>(
  emitter: T,
  callback: (session: EventSession<T>) => TReturn,
): TReturn;
export function refEventEmitter(
  emitter: EventEmitter,
  ...args:
    | [endOnEventNames?: string | string[]]
    | [
        endOnEventNames: string | string[],
        callback: (session: EventSession) => unknown,
      ]
    | [callback: (session: EventSession) => unknown]
): unknown {
  let [endOnEventNames, callback] =
    args.length === 2
      ? args
      : isTupleElementTypeOf(args, 0, 'function')
      ? [undefined, args[0]]
      : [args[0], undefined];

  if (typeof endOnEventNames === 'string') {
    endOnEventNames = [endOnEventNames];
  }

  let session = new EventSession(emitter, undefined, endOnEventNames);

  if (callback) {
    return callback(session);
  } else {
    return session;
  }
}
