import type * as HTTP2 from 'http2';

const INITIAL_PING_DURATION = 100;

const PING_INTERVAL_FACTOR = 60;

export function setupSessionPing(session: HTTP2.Http2Session): void {
  let latestDuration = INITIAL_PING_DURATION;

  let timer: NodeJS.Timeout | undefined;

  session.on('close', () => {
    clearInterval(timer);
  });

  update();

  function update(): void {
    timer = setInterval(() => {
      session.ping((error, duration) => {
        if (error) {
          return;
        }

        latestDuration = duration;
        update();
      });
    }, latestDuration * PING_INTERVAL_FACTOR);
  }
}
