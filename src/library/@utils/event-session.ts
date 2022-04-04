import {EventEmitter} from 'events';

import isTypeOfProperty from 'is-typeof-property';

export class EventSession<
  TEndValue = void,
  TEventEmitter extends EventEmitter = EventEmitter,
> {
  private disposers: ((value: TEndValue | undefined) => void)[] = [];

  private _ended = false;

  readonly endedPromise: Promise<TEndValue | undefined>;

  private endedPromiseResolver!: (value: TEndValue | undefined) => void;

  constructor(
    private _emitter?: TEventEmitter,
    private _root?: EventSession<TEndValue>,
    private endOnEventNames?: string[],
  ) {
    if (endOnEventNames) {
      this.endOn(endOnEventNames);
    }

    this.endedPromise = new Promise(resolve => {
      this.endedPromiseResolver = resolve;
    });
  }

  get ended(): boolean {
    return this._ended;
  }

  get emitter(): TEventEmitter {
    let emitter = this._emitter;

    if (!emitter) {
      throw new Error('Emitter is not specified');
    }

    return emitter;
  }

  get root(): EventSession<TEndValue> {
    return this._root ?? this;
  }

  ref<TEventEmitter extends EventEmitter>(
    emitter: TEventEmitter,
  ): EventSession<TEndValue, TEventEmitter> {
    this.assertNotEnded();

    let subSession = new EventSession(emitter, this.root, this.endOnEventNames);

    this.disposers.push(value => subSession.end(value));

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

  end(value?: TEndValue): void {
    if (this.ended) {
      return;
    }

    let root = this._root;

    if (root) {
      root.end();
      return;
    }

    this._ended = true;

    for (let disposer of this.disposers) {
      disposer(value);
    }

    this.disposers.splice(0);

    this.endedPromiseResolver(value);
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

export function refEventEmitter<TEndValue, TEventEmitter extends EventEmitter>(
  emitter: TEventEmitter,
  endOnEventNames?: string | string[],
): EventSession<TEndValue, TEventEmitter>;
export function refEventEmitter<
  TEndValue,
  TEventEmitter extends EventEmitter,
  TReturn,
>(
  emitter: TEventEmitter,
  endOnEventNames: string | string[],
  callback: (session: EventSession<TEndValue, TEventEmitter>) => TReturn,
): TReturn;
export function refEventEmitter<
  TEndValue,
  TEventEmitter extends EventEmitter,
  TReturn,
>(
  emitter: TEventEmitter,
  callback: (session: EventSession<TEndValue, TEventEmitter>) => TReturn,
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
      : isTypeOfProperty(args, 0, 'function')
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
