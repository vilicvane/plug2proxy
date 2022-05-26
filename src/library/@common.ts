import type * as HTTP2 from 'http2';
import type {Writable} from 'stream';

/**
 * A case-insensitive RegExp to match "hop by hop" headers.
 */
export const HOP_BY_HOP_HEADERS_REGEX = new RegExp(
  `^(${[
    'Connection',
    'Keep-Alive',
    'Proxy-Authenticate',
    'Proxy-Authorization',
    'TE',
    'Trailers',
    'Transfer-Encoding',
    'Upgrade',
  ].join('|')})$`,
  'i',
);

export function writeHTTPHead(
  socket: Writable,
  status: number,
  message: string,
  endAndDestroy = false,
): void {
  socket.write(`HTTP/1.1 ${status} ${message}\r\n\r\n`);

  if (endAndDestroy) {
    socket.end();
    destroyOnDrain(socket);
  }
}

export function destroyOnDrain(socket: Writable): void {
  if (socket.destroyed) {
    return;
  }

  if (!socket.writable || socket.writableLength === 0) {
    socket.destroy();
    return;
  }

  socket.on('drain', () => {
    socket.destroy();
  });
}

export function closeOnDrain(stream: HTTP2.Http2Stream): void {
  if (stream.closed) {
    return;
  }

  if (!stream.writable || stream.writableLength === 0) {
    stream.close();
    return;
  }

  stream.on('drain', () => {
    stream.close();
  });
}
