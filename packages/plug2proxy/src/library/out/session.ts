import * as HTTP from 'http';
import * as HTTP2 from 'http2';
import * as Net from 'net';

import {HOP_BY_HOP_HEADERS_REGEX, closeOnDrain} from '../@common';
import {groupRawHeaders} from '../@utils';
import {InRoute} from '../types';

import {Client} from './client';

export class Session {
  private id = '-';

  remoteAddress: string | undefined;

  private http2Client: HTTP2.ClientHttp2Session;

  constructor(readonly client: Client) {
    let http2Client = HTTP2.connect(
      client.connectAuthority,
      client.connectOptions,
    )
      .on('stream', (pushStream, headers) => {
        switch (headers.type) {
          case 'connect':
            void this.connect(pushStream, headers);
            break;
          case 'request':
            void this.request(pushStream, headers);
            break;
          case 'route':
            void this.route(pushStream, headers);
            break;
          default:
            console.error(
              `[${this.id}] received unexpected push stream "${headers.type}".`,
            );
            break;
        }
      })
      .on('close', () => {
        console.debug(`[${this.id}] session "close"`);
        client.removeSession(this);
      })
      .on('error', error => {
        console.error(`[${this.id}] session error:`, error.message);
      });

    this.http2Client = http2Client;

    let sessionStream = this.requestServer(
      '-',
      'session',
      {
        type: 'session',
        password: client.password,
      },
      {
        endStream: false,
      },
    )
      .prependListener('ready', () => {
        this.id = sessionStream.id!.toString();
      })
      .on('response', headers => {
        let status = headers[':status'];

        if (status === 200) {
          console.info(`[${this.id}] session ready.`);
        } else {
          console.error(
            `[${this.id}] session initialize error (${status}):`,
            headers.message,
          );
        }
      })
      .on('close', () => {
        console.debug(`[${this.id}] session stream "close".`);
        http2Client.close();
      })
      .on('error', error => {
        console.error(`[${this.id}] session stream error:`, error.message);
      });
  }

  private async connect(
    pushStream: HTTP2.ClientHttp2Stream,
    headers: HTTP2.IncomingHttpHeaders,
  ): Promise<void>;
  private async connect(
    pushStream: HTTP2.ClientHttp2Stream,
    {host, port}: {host: string; port: string},
  ): Promise<void> {
    const client = this.client;

    let id = pushStream.id!.toString();

    let logPrefix = `[${id}]`;

    console.info(`${logPrefix} connect: ${host}:${port}`);

    this.client.addActiveStream(
      'push',
      `connect ${host}:${port}`,
      this.id,
      pushStream.id!.toString(),
      pushStream,
    );

    let route: string;

    try {
      route = await client.router.route(host!);

      if (pushStream.closed) {
        console.debug(`${logPrefix} connect push stream closed while routing.`);
        return;
      }
    } catch (error: any) {
      console.error(`${logPrefix} route error:`, error.message);
      route = 'direct';
    }

    console.info(`${logPrefix} connect routed ${host} to ${route}.`);

    if (route === 'direct') {
      this.requestServer(id, `connect-direct ${host}`, {
        id,
        type: 'connect-direct',
      }).on('error', error => {
        console.error(
          `${logPrefix} connect-direct stream error:`,
          error.message,
        );
      });

      return;
    }

    console.debug(`${logPrefix} connecting...`);

    let inStream: HTTP2.ClientHttp2Stream | undefined;

    let outSocket = Net.createConnection({host, port: Number(port)})
      .on('connect', () => {
        console.debug(`${logPrefix} connected.`);

        inStream = this.requestServer(
          id,
          `connect-ok ${host}:${port}`,
          {
            id,
            type: 'connect-ok',
          },
          {
            endStream: false,
          },
        );

        inStream.pipe(outSocket);
        outSocket.pipe(inStream);

        inStream
          .on('end', () => {
            console.debug(`${logPrefix} in stream "end".`);
          })
          .on('close', () => {
            console.debug(`${logPrefix} in stream "close".`);
            outSocket.destroy();
          })
          .on('error', error => {
            console.error(`${logPrefix} in stream error:`, error.message);
          });
      })
      .on('end', () => {
        console.debug(`${logPrefix} out socket "end".`);
      })
      .on('close', () => {
        console.debug(`${logPrefix} out socket "close".`);

        if (inStream) {
          closeOnDrain(inStream);
        }
      })
      .on('error', error => {
        console.error(`${logPrefix} out socket error:`, error.message);
      });

    pushStream.on('close', () => {
      console.debug(`${logPrefix} connect push stream "close".`);
      inStream?.close();
      outSocket.destroy();
    });
  }

  private async request(
    requestStream: HTTP2.ClientHttp2Stream,
    headers: HTTP2.IncomingHttpHeaders,
  ): Promise<void>;
  private async request(
    requestStream: HTTP2.ClientHttp2Stream,
    {
      id,
      method,
      url,
      headers: headersJSON,
    }: {
      id: string | undefined;
      method: string;
      url: string;
      headers: string;
    },
  ): Promise<void> {
    if (!id) {
      id = requestStream.id!.toString();
    }

    let logPrefix = `[${id}]`;

    console.info(`${logPrefix} request:`, method, url);

    this.client.addActiveStream(
      'push',
      `request ${method} ${url}`,
      this.id,
      requestStream.id!.toString(),
      requestStream,
    );

    let headers = JSON.parse(headersJSON as string);

    let responded = false;

    let proxyRequest = HTTP.request(
      url as string,
      {
        method: method as string,
        headers,
      },
      proxyResponse => {
        let status = proxyResponse.statusCode!;

        console.debug(`${logPrefix} response received.`);

        let headers: {[key: string]: string | string[]} = {};

        for (let [key, value] of groupRawHeaders(proxyResponse.rawHeaders)) {
          if (HOP_BY_HOP_HEADERS_REGEX.test(key)) {
            continue;
          }

          let existingValue = headers[key];

          if (Array.isArray(existingValue)) {
            existingValue.push(value);
          } else if (existingValue !== undefined) {
            headers[key] = [existingValue, value];
          } else {
            headers[key] = value;
          }
        }

        let responseStream = this.requestServer(
          id,
          `response-stream ${url}`,
          {
            id,
            type: 'response-stream',
            status,
            headers: JSON.stringify(headers),
          },
          {
            endStream: false,
          },
        );

        responded = true;

        proxyResponse.pipe(responseStream);

        proxyResponse
          .on('end', () => {
            console.debug(`${logPrefix} proxy response "end".`);
          })
          .on('close', () => {
            console.debug(`${logPrefix} proxy response "close".`);
            closeOnDrain(responseStream);
          })
          .on('error', error => {
            console.error(`${logPrefix} proxy response error:`, error.message);
          });

        responseStream
          .on('close', () => {
            console.debug(`${logPrefix} response stream "close".`);
            proxyResponse.destroy();
          })
          .on('error', error => {
            console.error(`${logPrefix} response stream error:`, error.message);
          });
      },
    );

    requestStream.pipe(proxyRequest);

    requestStream
      .on('end', () => {
        console.debug(`${logPrefix} request stream "end".`);
      })
      .on('close', () => {
        console.debug(`${logPrefix} request stream "close".`);
      })
      .on('error', error => {
        proxyRequest.destroy();
        console.error(`${logPrefix} request stream error:`, error.message);
      });

    // Seems that ClientRequest does not have "close" event.
    proxyRequest.on('error', error => {
      console.error(`${logPrefix} proxy request error:`, error.message);

      if (responded) {
        return;
      }

      let responseStream: HTTP2.ClientHttp2Stream;

      if ((error as any).code === 'ENOTFOUND') {
        responseStream = this.requestServer(
          id,
          `response-stream (404) ${url}`,
          {
            id,
            type: 'response-stream',
            status: 404,
          },
        );
      } else {
        responseStream = this.requestServer(
          id,
          `response-stream (500) ${url}`,
          {
            id,
            type: 'response-stream',
            status: 500,
          },
        );
      }

      responseStream.on('error', error => {
        console.error(
          `${logPrefix} error response stream error:`,
          error.message,
        );
      });
    });
  }

  private async route(
    pushStream: HTTP2.ClientHttp2Stream,
    headers: HTTP2.IncomingHttpHeaders,
  ): Promise<void>;
  private async route(
    pushStream: HTTP2.ClientHttp2Stream,
    {host}: {host: string},
  ): Promise<void> {
    pushStream.close();

    let id = pushStream.id!.toString();

    let logPrefix = `[${id}]`;

    console.info(`${logPrefix} route:`, host);

    let sourceRoute = await this.client.router.route(host!);

    let route: InRoute = sourceRoute === 'direct' ? 'direct' : 'proxy';

    console.info(`${logPrefix} route routed ${host} to ${route}.`);

    this.requestServer(id, `route-result ${host}`, {
      id,
      type: 'route-result',
      route,
    })
      .on('end', () => {
        console.debug(`${logPrefix} route response stream "end".`);
      })
      .on('error', error => {
        console.error(
          `${logPrefix} route response stream error:`,
          error.message,
        );
      });
  }

  private requestServer(
    pushStreamId: string | undefined,
    description: string,
    headers: HTTP2.OutgoingHttpHeaders,
    options?: HTTP2.ClientSessionRequestOptions,
  ): HTTP2.ClientHttp2Stream {
    let stream = this.http2Client.request(headers, options);

    stream.on('ready', () => {
      this.client.addActiveStream(
        'request',
        description,
        this.id,
        pushStreamId,
        stream,
      );
    });

    return stream;
  }
}
