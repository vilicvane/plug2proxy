import assert from 'assert';
import type {Http2Session} from 'http2';

import bytes from 'bytes';

import {setupSessionPing} from './@utils/index.js';

const BANDWIDTH_CALCULATION_INTERVAL = 200;

const WINDOW_SIZE_FACTOR = 2;

const WINDOW_SIZE_REDUCING_RTT_THRESHOLD_FACTOR = 5;

const MIN_WINDOW_SIZE = bytes('64KB');

export function setupAutoWindowSize(
  session: Http2Session,
  initialWindowSize: number,
  callback: (windowSize: number) => void,
): void {
  assert(initialWindowSize >= MIN_WINDOW_SIZE);

  let rtt: number | undefined;
  let minRTT: number | undefined;

  setupSessionPing(session, duration => {
    rtt = duration;
    minRTT = Math.min(minRTT ?? Infinity, rtt);
  });

  session.setLocalWindowSize(initialWindowSize);

  let received = 0;

  let bandwidthCalculatedAt = Date.now();

  const timer = setInterval(() => {
    const now = Date.now();

    const duration = now - bandwidthCalculatedAt;
    const receivedSinceLastCalculation = received;

    received = 0;
    bandwidthCalculatedAt = now;

    if (duration <= 0) {
      return;
    }

    const {effectiveLocalWindowSize} = session.state;

    assert(effectiveLocalWindowSize !== undefined);

    const bandwidth = receivedSinceLastCalculation / duration; // bytes/ms

    if (minRTT === undefined || rtt === undefined) {
      return;
    }

    const refWindowSize = bandwidth * minRTT;

    const windowSize = Math.max(
      Math.ceil(refWindowSize * WINDOW_SIZE_FACTOR),
      MIN_WINDOW_SIZE,
    );

    if (
      windowSize > effectiveLocalWindowSize ||
      (windowSize < effectiveLocalWindowSize &&
        rtt > minRTT * WINDOW_SIZE_REDUCING_RTT_THRESHOLD_FACTOR)
    ) {
      session.setLocalWindowSize(windowSize);
      callback(windowSize);
    }
  }, BANDWIDTH_CALCULATION_INTERVAL);

  session
    .on('stream', stream => {
      const push = stream.push;

      stream.push = function (data: Buffer | null) {
        if (data) {
          received += data.length;
        }

        return push.call(stream, data);
      };
    })
    .on('close', () => clearInterval(timer));
}
