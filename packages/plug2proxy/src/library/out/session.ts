import * as HTTP from 'http';
import * as HTTP2 from 'http2';
import * as Net from 'net';

import {HOP_BY_HOP_HEADERS_REGEX} from '../@common';
import {groupRawHeaders} from '../@utils';
import {InRoute} from '../types';

import {Client} from './client';

export class Session {
  remoteAddress: string | undefined;

  private http2Client: HTTP2.ClientHttp2Session;

  constructor(readonly client: Client) {
    console.info('initializing session...');

    let http2Client = HTTP2.connect(
      client.connectAuthority,
      client.connectOptions,
    );

    let session = http2Client.request({
      type: 'initialize',
      password: client.password,
    });

    session
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
      .on('error', (error: any) => {
        console.error('session error:', error.code, error.message);
      });

    http2Client
      .on('stream', (pushStream, headers) => {
        switch (headers.type) {
          case 'connect':
            void this.connect(headers);
            break;
          case 'request':
            void this.request(headers, pushStream);
            break;
          case 'route':
            void this.route(headers);
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
        console.error('session error:', error.code, error.message);
      });

    this.http2Client = http2Client;
  }

  private async connect({
    id,
    host,
    port,
  }: HTTP2.IncomingHttpHeaders): Promise<void> {
    let client = this.client;

    console.info('connect:', `${host}:${port}`);

    let route: string;

    try {
      route = await client.router.route(host!);
    } catch (error: any) {
      console.error('route error:', error.code, error.message);
      route = 'direct';
    }

    console.info(`connect routed ${host} to ${route}.`);

    if (route === 'direct') {
      this.http2Client.request({
        id,
        type: 'connect-direct',
      });

      return;
    }

    console.debug(`connecting ${host}:${port}...`);

    let outSocket = Net.createConnection({host, port: Number(port)});
    let inStream: HTTP2.ClientHttp2Stream | undefined;

    outSocket.on('connect', () => {
      console.debug(`connected ${host}:${port}.`);

      inStream = this.http2Client.request(
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
        .on('close', () => {
          console.debug('in stream "close".');
        })
        .on('error', error => {
          console.error('in stream error:', error.code, error.message);
          outSocket.end();
        });
    });

    outSocket
      .on('close', () => {
        console.debug('out socket "close".');
      })
      .on('error', (error: any) => {
        console.error('out socket error:', error.code, error.message);
        inStream?.close();
      });
  }

  private async request(
    {id, method, url, headers: headersJSON}: HTTP2.IncomingHttpHeaders,
    requestStream: HTTP2.ClientHttp2Stream,
  ): Promise<void> {
    console.info('request:', method, url);

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

        let responseStream = this.http2Client.request(
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
          .on('error', (error: any) => {
            console.error('proxy response error:', error.code, error.message);
            responseStream.end();
          });

        responseStream.on('error', error => {
          console.error('response stream error:', error.code, error.message);
          proxyResponse.destroy();
        });
      },
    );

    requestStream.pipe(proxyRequest);

    requestStream
      .on('end', () => {
        console.debug('request stream "end".');
      })
      .on('error', (error: any) => {
        console.error('request stream error:', error.code, error.message);
        proxyRequest.end();
      });

    proxyRequest.on('error', (error: any) => {
      console.error('proxy request error:', error.code, error.message);

      if (responded) {
        return;
      }

      if (error.code === 'ENOTFOUND') {
        this.http2Client.request({
          id,
          type: 'response-stream',
          status: 404,
        });
      } else {
        this.http2Client.request({
          id,
          type: 'response-stream',
          status: 500,
        });
      }
    });
  }

  private async route({id, host}: HTTP2.IncomingHttpHeaders): Promise<void> {
    console.info('route:', host);

    let sourceRoute = await this.client.router.route(host!);
    let route: InRoute = sourceRoute === 'direct' ? 'direct' : 'proxy';

    console.info(`route routed ${host} to ${route}.`);

    this.http2Client.request({
      id,
      type: 'route-result',
      route,
    });
  }
}
