export function groupRawHeaders(rawHeaders: string[]): [string, string][] {
  let headers: [string, string][] = [];

  for (let i = 0; i < rawHeaders.length; i += 2) {
    headers.push([rawHeaders[i], rawHeaders[i + 1]]);
  }

  return headers;
}

export function timeout<T>(
  competitor: Promise<unknown> | (() => Promise<T>),
  duration: number,
  error?: string | Error | (() => Error),
): Promise<T>;
export function timeout(
  duration: number,
  error?: string | Error | (() => Error),
): Promise<never>;
export function timeout(
  ...args:
    | [
        competitor: Promise<unknown> | (() => Promise<unknown>),
        duration: number,
        error?: string | Error | (() => Error),
      ]
    | [duration: number, error?: string | Error | (() => Error)]
): Promise<unknown> {
  let [competitor, duration, error] = isTupleElementTypeOf(args, 0, 'number')
    ? [undefined, ...args]
    : args;

  let timeoutRejection = new Promise((_resolve, reject) => {
    setTimeout(() => {
      if (typeof error === 'function') {
        error = error();
      } else if (typeof error === 'string') {
        error = new Error(error);
      }

      reject(error ?? new Error('Timeout'));
    }, duration);
  });

  if (competitor) {
    if (typeof competitor === 'function') {
      competitor = competitor();
    }

    return Promise.race([competitor, timeoutRejection]);
  } else {
    return timeoutRejection;
  }
}

export function isTupleElementTypeOf<
  T extends any[],
  TIndex extends number,
  TType extends
    | 'string'
    | 'number'
    | 'bigint'
    | 'boolean'
    | 'symbol'
    | 'undefined'
    | 'object'
    | 'function',
>(
  tuple: T,
  index: TIndex,
  type: TType,
): tuple is Extract<T, {[TKey in TIndex]: TypeOfTypeOfString<TType>}> {
  return typeof tuple[index] === type;
}

export type TypeOfTypeOfString<TType extends string> = TType extends 'string'
  ? string
  : TType extends 'number'
  ? number
  : TType extends 'bigint'
  ? bigint
  : TType extends 'boolean'
  ? boolean
  : TType extends 'symbol'
  ? symbol
  : TType extends 'undefined'
  ? undefined
  : TType extends 'object'
  ? object
  : TType extends 'function'
  ? (...args: any[]) => any
  : never;
