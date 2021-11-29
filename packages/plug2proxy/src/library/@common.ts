import {Duplex, Readable, Transform, Writable} from 'stream';

import {StreamJet} from 'socket-jet';

import {InOutData, StreamChunkData, StreamEndData} from './types';

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
  let onError = (): void => {
    destination.end();
  };

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

              jet.off('error', onError);
              break;
            default:
              throw new Error(`Unexpected Jet data "${data.type}"`);
          }
        },
      }),
    )
    .pipe(destination);

  jet.once('error', onError);
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

  source.on('error', () => {
    source.unpipe();

    let data: StreamEndData = {
      type: 'stream-end',
    };

    jet.write(data);
  });

  source.on('end', () => {
    source.unpipe();

    let data: StreamEndData = {
      type: 'stream-end',
    };

    jet.write(data);
  });
}
