import {Duplex, Readable, Transform, Writable} from 'stream';

import {StreamJet} from 'socket-jet';

import {StreamPacket} from './packets';

// create a case-insensitive RegExp to match "hop by hop" headers
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

export function pipeJetToBufferStream(
  jet: StreamJet<unknown, unknown, Duplex>,
  destination: Writable,
): void;
export function pipeJetToBufferStream(
  jet: StreamJet<StreamPacket, StreamPacket, Duplex>,
  destination: Writable,
): void {
  let transform = new Transform({
    writableObjectMode: true,
    transform(data: StreamPacket, _encoding, callback) {
      switch (data.type) {
        case 'stream-chunk':
          this.push(data.chunk);
          callback();
          break;
        case 'stream-end':
          this.push(null);
          callback();

          jet.unpipe(this);

          if (jet.listenerCount('data') > 0) {
            jet.resume();
          }

          break;
      }
    },
  });

  jet.pipe(transform).pipe(destination);
}

export function pipeBufferStreamToJet(
  source: Readable,
  jet: StreamJet<unknown, unknown, Duplex>,
): void;
export function pipeBufferStreamToJet(
  source: Readable,
  jet: StreamJet<StreamPacket, StreamPacket, Duplex>,
): void {
  let transform = new Transform({
    readableObjectMode: true,
    transform(chunk: Buffer, _encoding, callback) {
      this.push({
        type: 'stream-chunk',
        chunk,
      });

      callback();
    },
    flush(callback) {
      this.push({
        type: 'stream-end',
      });

      callback();
    },
  });

  source.pipe(transform).pipe(jet as Writable, {end: false});
}

export function writeHTTPHead(
  socket: Writable,
  status: number,
  message: string,
  end = false,
): void {
  socket.write(`HTTP/1.1 ${status} ${message}\r\n\r\n`);

  if (end) {
    socket.end();
  }
}
