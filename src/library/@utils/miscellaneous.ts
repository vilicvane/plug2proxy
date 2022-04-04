import isTypeOfProperty from 'is-typeof-property';

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
  let [competitor, duration, error] = isTypeOfProperty(args, 0, 'number')
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
