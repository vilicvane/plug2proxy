import {PassThrough, type Readable} from 'stream';

import {HTTPParser} from 'http-parser-js';
import {readTlsClientHello} from 'read-tls-client-hello';
import SPDYTransport from 'spdy-transport';

const REQUEST_LINE_PATTERN = /^([A-Z]+) (\S+) HTTP\/(1\.[01]|2\.0)\r\n/;

const REQUEST_METHOD_PATTERN = /^[A-Z]+ ?/;

const NON_PRINTABLE_ASCII_PATTERN = /[^\x20-\x7F]/;

export type HTTPType = 'http1' | 'http2';

export type ReadHTTPHeaderResult = {
  type: HTTPType;
  headerMap: Map<string, string>;
};

export async function readHTTPHeaders(
  stream: Readable,
): Promise<ReadHTTPHeaderResult | undefined> {
  const type = await new Promise<HTTPType | undefined>((resolve, reject) => {
    const chunks: Buffer[] = [];

    const onData = (data: Buffer): void => {
      chunks.push(data);

      const consumed = Buffer.concat(chunks);

      const text = consumed.toString('ascii');

      const groups = REQUEST_LINE_PATTERN.exec(text);

      let type: HTTPType | undefined;

      if (groups) {
        const [, method, uri, version] = groups;

        switch (version) {
          case '1.0':
          case '1.1':
            type = 'http1';
            break;
          case '2.0':
            if (method === 'PRI' && uri === '*') {
              type = 'http2';
            }
            break;
        }
      } else {
        if (NON_PRINTABLE_ASCII_PATTERN.test(text)) {
          // No need to wait for more data if there are non-printable ASCII
          // characters.
        } else if (!REQUEST_METHOD_PATTERN.test(text)) {
          // No need to wait for more data if it doesn't look like a request.
        } else {
          // Wait for more data.
          return;
        }
      }

      stream.off('data', onData);
      stream.off('error', reject);

      stream.pause();
      stream.unshift(consumed);

      resolve(type);
    };

    stream.on('data', onData);
    stream.on('error', reject);
  });

  switch (type) {
    case 'http1':
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

          resolve({
            type: 'http1',
            headerMap,
          });
        };

        const onData = (data: Buffer): void => {
          chunks.push(data);
          parser.execute(data);
        };

        stream.on('data', onData);
        stream.on('error', reject);

        stream.resume();
      });
    case 'http2':
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

          resolve({
            type: 'http2',
            headerMap: new Map(Object.entries(data.headers)),
          });
        });

        const onData = (data: Buffer): void => {
          chunks.push(data);
          parser.write(data);
        };

        stream.on('data', onData);
        stream.on('error', reject);

        stream.resume();
      });

    default:
      return undefined;
  }
}

export type ReadTLSResult = {
  type: 'tls';
  serverName: string | undefined;
  alpnProtocols: string[] | undefined;
};

export type ReadHTTPHeadersOrTLSResult = ReadHTTPHeaderResult | ReadTLSResult;

export async function readHTTPHeadersOrTLS(
  stream: Readable,
): Promise<ReadHTTPHeadersOrTLSResult | undefined> {
  let httpHeaderResult: ReadHTTPHeaderResult | undefined;

  try {
    httpHeaderResult = await readHTTPHeaders(stream);
  } catch (error) {
    return undefined;
  }

  if (httpHeaderResult) {
    return httpHeaderResult;
  }

  const helloThrough = new PassThrough();

  const helloChunks: Buffer[] = [];

  const onHelloData = (data: Buffer): void => {
    helloChunks.push(data);
    helloThrough.write(data);
  };

  stream.on('data', onHelloData);
  stream.resume();

  try {
    const {serverName, alpnProtocols} = await readTlsClientHello(helloThrough);

    return {
      type: 'tls',
      serverName,
      alpnProtocols,
    };
  } catch (error) {
    return undefined;
  } finally {
    stream.off('data', onHelloData);

    stream.pause();

    stream.unshift(Buffer.concat(helloChunks));
  }
}
