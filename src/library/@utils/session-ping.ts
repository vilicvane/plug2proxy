import type * as HTTP2 from 'http2';

const INITIAL_PING_DURATION = 100;

const PING_INTERVAL_FACTOR = 50;

export function setupSessionPing(
  session: HTTP2.Http2Session,
  durationCallback: (duration: number) => void,
): void {
  let timer: NodeJS.Timeout | undefined;

  session.on('close', () => clearInterval(timer));

  ping();
  update(INITIAL_PING_DURATION);

  function update(duration: number): void {
    clearInterval(timer);

    timer = setInterval(() => ping(), duration * PING_INTERVAL_FACTOR);
  }

  function ping(): void {
    if (session.destroyed) {
      clearInterval(timer);
      return;
    }

    session.ping((error, duration) => {
      if (error) {
        return;
      }

      durationCallback(duration);
      update(duration);
    });
  }
}
