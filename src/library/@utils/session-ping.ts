import type * as HTTP2 from 'http2';

const INITIAL_PING_DURATION = 100;

const PING_INTERVAL_FACTOR = 60;

export function setupSessionPing(session: HTTP2.Http2Session): void {
  let timer: NodeJS.Timeout | undefined;

  session.on('close', () => clearInterval(timer));

  update(INITIAL_PING_DURATION);

  function update(duration: number): void {
    clearInterval(timer);

    timer = setInterval(() => {
      if (session.destroyed) {
        clearInterval(timer);
        return;
      }

      session.ping((error, duration) => {
        if (error) {
          return;
        }

        update(duration);
      });
    }, duration * PING_INTERVAL_FACTOR);
  }
}
