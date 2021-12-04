import * as HTTP2 from 'http2';
import {Duplex, Readable, Transform, Writable} from 'stream';

import {StreamJet} from 'socket-jet';

import {InOutPacket, OutInPacket, StreamPacket} from './packets';

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
  jet: StreamJet<unknown, unknown, Duplex>,
  destination: Writable,
): void {
  let cleanedUp = false;

  let transform = new Transform({
    writableObjectMode: true,
    transform(packet: InOutPacket | OutInPacket, _encoding, callback) {
      switch (packet.type) {
        case 'stream-chunk':
          this.push(packet.chunk);
          callback();
          break;
        case 'stream-end':
          this.push(null);
          callback();
          cleanUp();
          break;
        case 'ping':
        case 'pong':
          break;
        default:
          this.push(null);
          cleanUp();
          break;
      }
    },
  });

  jet.pipe(transform).pipe(destination);

  destination.on('error', cleanUp);
  destination.on('end', cleanUp);
  destination.on('close', cleanUp);

  function cleanUp(): void {
    if (cleanedUp) {
      return;
    }

    cleanedUp = true;

    jet.unpipe();
    jet.resume();
  }
}

export function pipeBufferStreamToJet(
  source: Readable,
  jet: StreamJet<unknown, unknown, Duplex>,
): void;
export function pipeBufferStreamToJet(
  source: Readable,
  jet: StreamJet<StreamPacket, StreamPacket, Duplex>,
): void {
  let cleanedUp = false;

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
      cleanUp();
      callback();
    },
  });

  source.pipe(transform).pipe(jet as Writable, {end: false});

  source.on('error', cleanUp);
  source.on('end', cleanUp);
  source.on('close', cleanUp);

  function cleanUp(): void {
    if (cleanedUp) {
      return;
    }

    cleanedUp = true;

    if (jet.writable) {
      jet.write({
        type: 'stream-end',
      });
    }
  }
}

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

  if (socket.writableLength === 0) {
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

  if (stream.writableLength === 0) {
    stream.close();
    return;
  }

  stream.on('drain', () => {
    stream.close();
  });
}
