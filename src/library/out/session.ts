import * as HTTP from 'http';
import * as HTTP2 from 'http2';
import * as Net from 'net';
import {URL} from 'url';

import {HOP_BY_HOP_HEADERS_REGEX, closeOnDrain} from '../@common';
import {groupRawHeaders} from '../@utils';

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
          default:
            console.error(
              `[${this.id}] received unexpected push stream ${headers.type}.`,
            );
            pushStream.close();
            break;
        }
      })
      .on('close', () => {
        console.debug(`[${this.id}] session "close"`);
      })
      .on('error', error => {
        console.error(`[${this.id}] session error:`, error.message);
      });

    this.http2Client = http2Client;

    let sessionStream = http2Client
      .request(
        {
          type: 'session',
          password: client.password,
        },
        {
          endStream: false,
        },
      )
      .on('response', headers => {
        let status = headers[':status'];

        if (status === 200) {
          this.id = headers.id as string;
          console.info(`[${this.id}] session ready.`);
          client.addActiveStream('request', 'session', this.id, sessionStream);
        } else {
          console.error(
            `[${this.id}] session initialize error (${status}):`,
            headers.message,
          );
          sessionStream.close();
        }
      })
      .on('close', () => {
        console.debug(`[${this.id}] session stream "close".`);
        client.removeSession(this);
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

    let id = `${this.id}:${pushStream.id}`;

    console.info(`[${id}] connect: ${host}:${port}`);

    client.addActiveStream('push', `connect ${host}:${port}`, id, pushStream);

    let logPrefix = `[${id}][${host}]`;

    pushStream
      .on('end', () => {
        console.debug(`${logPrefix} connect push stream "end".`);
      })
      .on('close', () => {
        console.debug(`${logPrefix} connect push stream "close".`);
      })
      .on('error', error => {
        console.debug(`${logPrefix} connect push stream error:`, error.message);
      });

    let route: string;

    try {
      route = await client.router.route(host);

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

      pushStream.close();

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

        pushStream.close();

        if (inStream) {
          closeOnDrain(inStream);
        }
      })
      .on('error', error => {
        console.error(`${logPrefix} out socket error:`, error.message);
      });

    // Debugging logs added at the beginning of `connect()`.
    pushStream.on('close', () => {
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
      method,
      url,
      headers: headersJSON,
    }: {
      method: string;
      url: string;
      headers: string;
    },
  ): Promise<void> {
    const client = this.client;

    let id = `${this.id}:${requestStream.id}`;

    console.info(`[${id}] request:`, method, url);

    let host = new URL(url).hostname;

    client.addActiveStream(
      'push',
      `request ${method} ${url}`,
      id,
      requestStream,
    );

    let logPrefix = `[${id}][${host}]`;

    requestStream
      .on('end', () => {
        console.debug(`${logPrefix} request stream "end".`);
      })
      .on('close', () => {
        console.debug(`${logPrefix} request stream "close".`);
      })
      .on('error', error => {
        console.debug(`${logPrefix} request stream error:`, error.message);
      });

    let route: string;

    try {
      route = await client.router.route(host);

      if (requestStream.closed && !requestStream.readableEnded) {
        console.debug(`${logPrefix} push stream closed while routing.`);
        return;
      }
    } catch (error: any) {
      console.error(`${logPrefix} route error:`, error.message);
      route = 'direct';
    }

    console.info(`${logPrefix} request routed ${host} to ${route}.`);

    if (route === 'direct') {
      this.requestServer(id, `request-direct ${host}`, {
        id,
        type: 'request-direct',
      }).on('error', error => {
        console.error(
          `${logPrefix} request-direct stream error:`,
          error.message,
        );
      });

      requestStream.close();

      return;
    }

    console.debug(`${logPrefix} requesting...`);

    let headers = JSON.parse(headersJSON);

    let responded = false;

    let proxyRequest = HTTP.request(
      url,
      {
        method,
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

    // Debugging logs added at the beginning of `request()`.
    requestStream.on('close', () => {
      if (requestStream.readableEnded) {
        return;
      }

      proxyRequest.destroy();
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

  private requestServer(
    id: string,
    description: string,
    headers: HTTP2.OutgoingHttpHeaders,
    options?: HTTP2.ClientSessionRequestOptions,
  ): HTTP2.ClientHttp2Stream {
    let stream = this.http2Client.request(headers, options);

    this.client.addActiveStream('request', description, id, stream);

    return stream;
  }
}
