import {type Readable} from 'stream';

import {HTTPParser} from 'http-parser-js';
import SPDYTransport from 'spdy-transport';

const HTTP2_START_LINE = 'PRI * HTTP/2.0\r\n\r\n';

/**
 * It seems that if `.resume()` is needed for 'data' events after `.pause()`.
 */
export async function readHTTPRequestStreamHeaders(
  stream: Readable,
): Promise<Map<string, string>> {
  const http2 = await new Promise<boolean>((resolve, reject) => {
    const chunks: Buffer[] = [];

    const onData = (data: Buffer): void => {
      chunks.push(data);

      const consumed = Buffer.concat(chunks);

      if (consumed.length < HTTP2_START_LINE.length) {
        return;
      }

      stream.off('data', onData);
      stream.off('error', reject);

      stream.pause();
      stream.unshift(consumed);

      resolve(
        consumed.toString('utf8', 0, HTTP2_START_LINE.length) ===
          HTTP2_START_LINE,
      );
    };

    stream.on('data', onData);
    stream.on('error', reject);
  });

  if (http2) {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];

      const pool = SPDYTransport.protocol.http2.compressionPool.create();

      const parser = SPDYTransport.protocol.http2.parser.create({});

      parser.setCompression(pool.get());

      parser.on('data', data => {
        if (data.type !== 'HEADERS') {
          return;
        }

        stream.off('data', onData);
        stream.off('error', reject);

        stream.pause();

        stream.unshift(Buffer.concat(chunks));

        resolve(new Map(Object.entries(data.headers)));
      });

      const onData = (data: Buffer): void => {
        chunks.push(data);
        parser.write(data);
      };

      stream.on('data', onData);
      stream.on('error', reject);

      stream.resume();
    });
  } else {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];

      const parser = new HTTPParser(HTTPParser.REQUEST);

      parser.onHeadersComplete = ({headers}) => {
        const headerMap = new Map<string, string>();

        for (let index = 0; index < headers.length; index += 2) {
          headerMap.set(headers[index].toLowerCase(), headers[index + 1]);
        }

        stream.off('data', onData);
        stream.off('error', reject);

        stream.pause();

        stream.unshift(Buffer.concat(chunks));

        resolve(headerMap);
      };

      const onData = (data: Buffer): void => {
        chunks.push(data);
        parser.execute(data);
      };

      stream.on('data', onData);
      stream.on('error', reject);

      stream.resume();
    });
  }
}
