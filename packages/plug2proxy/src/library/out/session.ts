import * as HTTP from 'http';
import * as HTTP2 from 'http2';
import * as Net from 'net';

import {HOP_BY_HOP_HEADERS_REGEX, closeOnDrain} from '../@common';
import {groupRawHeaders} from '../@utils';
import {InRoute} from '../types';

import {Client} from './client';

export class Session {
  private id = ++Session.lastId;

  remoteAddress: string | undefined;

  private http2Client: HTTP2.ClientHttp2Session;

  constructor(readonly client: Client) {
    console.info('initializing session...');

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
            console.error('received unexpected push stream:', headers.type);
            break;
        }
      })
      .on('close', () => {
        console.debug('session "close".');
        client.removeSession(this);
      })
      .on('error', error => {
        console.error('session error:', error.message);
      });

    this.http2Client = http2Client;

    this.requestServer(
      'session',
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
          console.info('session ready.');
        } else {
          console.error(
            `session initialize error (${status}):`,
            headers.message,
          );
        }
      })
      .on('close', () => {
        console.debug('session stream "close".');
        http2Client.close();
      })
      .on('error', error => {
        console.error('session stream error:', error.message);
      });
  }

  private async connect(
    pushStream: HTTP2.ClientHttp2Stream,
    {id, host, port}: HTTP2.IncomingHttpHeaders,
  ): Promise<void> {
    let client = this.client;

    console.info('connect:', `${host}:${port}`);

    let route: string;

    try {
      route = await client.router.route(host!);

      if (pushStream.closed) {
        console.debug('connect push stream closed while routing:', host);
        return;
      }
    } catch (error: any) {
      console.error('route error:', error.message);
      route = 'direct';
    }

    console.info(`connect routed ${host} to ${route}.`);

    if (route === 'direct') {
      this.requestServer(`connect-direct ${host}`, {
        id,
        type: 'connect-direct',
      }).on('error', error => {
        console.error('connect-direct stream error:', error.message);
      });

      return;
    }

    console.debug(`connecting ${host}:${port}...`);

    let inStream: HTTP2.ClientHttp2Stream | undefined;

    let outSocket = Net.createConnection({host, port: Number(port)})
      .on('connect', () => {
        console.debug(`connected ${host}:${port}.`);

        inStream = this.requestServer(
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
            console.debug('in stream "end".');
          })
          .on('close', () => {
            console.debug('in stream "close".');
            outSocket.destroy();
          })
          .on('error', error => {
            console.error('in stream error:', error.message);
          });
      })
      .on('end', () => {
        console.debug('out socket "end".');
      })
      .on('close', () => {
        console.debug('out socket "close".');

        if (inStream) {
          closeOnDrain(inStream);
        }
      })
      .on('error', error => {
        console.error('out socket error:', error.message);
      });

    pushStream.on('close', () => {
      console.debug('connect push stream "close":', host, inStream?.id);
      inStream?.close();
      outSocket.destroy();
    });
  }

  private async request(
    requestStream: HTTP2.ClientHttp2Stream,
    {id, method, url, headers: headersJSON}: HTTP2.IncomingHttpHeaders,
  ): Promise<void> {
    console.info('request:', method, url);

    this.client.addActiveStream(
      'push',
      `request ${method} ${url}`,
      this.id,
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

        console.debug('response received.');

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
            console.debug('proxy response "end".');
          })
          .on('close', () => {
            console.debug('proxy response "close".');
            closeOnDrain(responseStream);
          })
          .on('error', error => {
            console.error('proxy response error:', error.message);
          });

        responseStream.on('data', () => {});

        responseStream
          .on('close', () => {
            console.debug('response stream "close".');
            proxyResponse.destroy();
          })
          .on('error', error => {
            console.error('response stream error:', error.message);
          });
      },
    );

    requestStream.pipe(proxyRequest);

    requestStream
      .on('end', () => {
        console.debug('request stream "end".');
      })
      .on('close', () => {
        console.debug('request stream "close".');
      })
      .on('error', error => {
        proxyRequest.destroy();
        console.error('request stream error:', error.message);
      });

    // Seems that ClientRequest does not have "close" event.
    proxyRequest.on('error', error => {
      console.error('proxy request error:', error.message);

      if (responded) {
        return;
      }

      let responseStream: HTTP2.ClientHttp2Stream;

      if ((error as any).code === 'ENOTFOUND') {
        responseStream = this.requestServer(`response-stream (404) ${url}`, {
          id,
          type: 'response-stream',
          status: 404,
        });
      } else {
        responseStream = this.requestServer(`response-stream (500) ${url}`, {
          id,
          type: 'response-stream',
          status: 500,
        });
      }

      responseStream.on('error', error => {
        console.error('error response stream error:', error.message);
      });
    });
  }

  private async route(
    pushStream: HTTP2.ClientHttp2Stream,
    {id, host}: HTTP2.IncomingHttpHeaders,
  ): Promise<void> {
    pushStream.close();

    console.info('route:', host);

    let sourceRoute = await this.client.router.route(host!);

    let route: InRoute = sourceRoute === 'direct' ? 'direct' : 'proxy';

    console.info(`route routed ${host} to ${route}.`);

    this.requestServer(`route-result ${host}`, {
      id,
      type: 'route-result',
      route,
    })
      .on('end', () => {
        console.debug('route response stream "end".');
      })
      .on('error', error => {
        console.error('route response stream error:', error.message);
      });
  }

  private requestServer(
    description: string,
    headers: HTTP2.OutgoingHttpHeaders,
    options?: HTTP2.ClientSessionRequestOptions,
  ): HTTP2.ClientHttp2Stream {
    let stream = this.http2Client.request(headers, options);

    this.client.addActiveStream('request', description, this.id, stream);

    return stream;
  }

  private static lastId = 0;
}
