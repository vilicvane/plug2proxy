import {Duplex, Readable, Transform, Writable} from 'stream';

import {StreamJet} from 'socket-jet';

import {InOutData, StreamChunkData} from './types';

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
): void {
  jet
    .pipe(
      new Transform({
        writableObjectMode: true,
        transform(data: InOutData, _encoding, callback) {
          switch (data.type) {
            case 'stream-chunk':
              this.push(data.chunk);
              callback();
              break;
            case 'stream-end':
              jet.unpipe();
              jet.resume();
              destination.end();
              break;
            default:
              throw new Error(`Unexpected Jet data "${data.type}"`);
          }
        },
      }),
    )
    .pipe(destination);
}

export function pipeBufferStreamToJet(
  source: Readable,
  jet: StreamJet<unknown, unknown, Duplex>,
): void {
  source
    .pipe(
      new Transform({
        readableObjectMode: true,
        transform(chunk: Buffer, _encoding, callback) {
          let data: StreamChunkData = {
            type: 'stream-chunk',
            chunk,
          };

          this.push(data);

          callback();
        },
      }),
    )
    .pipe(jet as Writable, {end: false});
}
