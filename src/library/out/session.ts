import * as HTTP from 'http';
import * as HTTP2 from 'http2';
import * as Net from 'net';
import {URL} from 'url';

import bytes from 'bytes';
import ms from 'ms';

import {HOP_BY_HOP_HEADERS_REGEX, closeOnDrain} from '../@common';
import {generateRandomAuthoritySegment, groupRawHeaders} from '../@utils';

import type {Client} from './client';

const SESSION_PING_INTERVAL = ms('5s');
const SESSION_MAX_OUTSTANDING_PINGS = 2;

const CLIENT_CONNECT_TIMEOUT = ms('5s');

const WINDOW_SIZE = bytes('32MB');

export class Session {
  private id = '-';

  remoteAddress: string | undefined;

  private http2Client: HTTP2.ClientHttp2Session;

  constructor(readonly client: Client) {
    let connectTimeout: NodeJS.Timeout | undefined;

    let connectAuthority = client.connectAuthority.replace(
      '#',
      generateRandomAuthoritySegment(),
    );

    console.info(`(${client.label}) session authority: ${connectAuthority}`);

    let connectOptions = client.connectOptions;

    let http2Client = HTTP2.connect(connectAuthority, {
      settings: {
        initialWindowSize: WINDOW_SIZE,
        ...connectOptions.settings,
      },
      maxOutstandingPings: SESSION_MAX_OUTSTANDING_PINGS,
      ...connectOptions,
    })
      .on('connect', () => {
        clearTimeout(connectTimeout!);

        http2Client.setLocalWindowSize(WINDOW_SIZE);

        let pingTimer = setInterval(() => {
          if (http2Client.destroyed) {
            clearInterval(pingTimer);
            return;
          }

          http2Client.ping(error => {
            if (!error) {
              return;
            }

            console.error(
              `(${client.label})[${this.id}] ping error:`,
              error.message,
            );

            http2Client.destroy();
          });
        }, SESSION_PING_INTERVAL);

        http2Client
          .on('close', () => {
            clearInterval(pingTimer);
          })
          .on('error', () => {
            clearInterval(pingTimer);
          });
      })
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
              `(${client.label})[${this.id}] received unexpected push stream ${headers.type}.`,
            );
            pushStream.destroy();
            break;
        }
      })
      .on('close', () => {
        console.debug(`(${client.label})[${this.id}] session "close".`);
      })
      .on('error', error => {
        console.error(
          `(${client.label})[${this.id}] session error:`,
          error.message,
        );
      });

    this.http2Client = http2Client;

    let sessionStream = http2Client
      .request(
        {
          type: 'session',
          password: client.password,
          priority: client.priority,
          'activation-latency': client.activationLatency,
          'deactivation-latency': client.deactivationLatency,
          'quality-deactivation-override': client.qualityDeactivationOverride,
          'quality-activation-override': client.qualityActivationOverride,
          'quality-measurement-duration': client.qualityMeasurementDuration,
        },
        {
          endStream: false,
        },
      )
      .on('response', headers => {
        let status = headers[':status'];

        if (status === 200) {
          this.id = headers.id as string;
          console.info(`(${client.label})[${this.id}] session ready.`);
          client.addActiveStream('request', 'session', this.id, sessionStream);
        } else {
          console.error(
            `(${client.label})[${this.id}] session initialize error (${status}):`,
            headers.message,
          );
          sessionStream.destroy();
        }
      })
      .on('close', () => {
        console.debug(`(${client.label})[${this.id}] session stream "close".`);
        client.removeSession(this);
      })
      .on('error', error => {
        console.error(
          `(${client.label})[${this.id}] session stream error:`,
          error.message,
        );
      });

    connectTimeout = setTimeout(() => {
      console.error(`(${client.label}) connect timeout.`);

      client.removeSession(this);

      sessionStream.destroy();
      http2Client.destroy();
    }, CLIENT_CONNECT_TIMEOUT);
  }

  private async connect(
    pushStream: HTTP2.ClientHttp2Stream,
    headers: HTTP2.IncomingHttpHeaders,
  ): Promise<void>;
  private async connect(
    pushStream: HTTP2.ClientHttp2Stream,
    {
      host,
      port,
      'host-ip': hostIP,
    }: {host: string; port: string; 'host-ip': string | undefined},
  ): Promise<void> {
    const client = this.client;

    let id = `${this.id}:${pushStream.id}`;

    console.info(`(${client.label})[${id}] connect: ${host}:${port}`);

    client.addActiveStream('push', `connect ${host}:${port}`, id, pushStream);

    let logPrefix = `(${client.label})[${id}][${host}]`;

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
      route = await client.router.route(this.id, host, hostIP);

      if (pushStream.destroyed) {
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

      pushStream.destroy();

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

        pushStream.destroy();

        if (inStream) {
          closeOnDrain(inStream);
        }
      })
      .on('error', error => {
        console.error(`${logPrefix} out socket error:`, error.message);
      });

    // Debugging logs added at the beginning of `connect()`.
    pushStream.on('close', () => {
      if (inStream) {
        closeOnDrain(inStream);
      }

      outSocket.destroy();
    });
  }

  private async request(
    requestStream: HTTP2.ClientHttp2Stream,
    headers: HTTP2.IncomingHttpHeaders,
  ): Promise<void>;
  private async request(
    pushStream: HTTP2.ClientHttp2Stream,
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

    let id = `${this.id}:${pushStream.id}`;

    console.info(`(${client.label})[${id}] request:`, method, url);

    let host = new URL(url).hostname;

    client.addActiveStream('push', `request ${method} ${url}`, id, pushStream);

    let logPrefix = `(${client.label})[${id}][${host}]`;

    pushStream
      .on('end', () => {
        console.debug(`${logPrefix} request push stream "end".`);
      })
      .on('close', () => {
        console.debug(`${logPrefix} request push stream "close".`);
      })
      .on('error', error => {
        console.debug(`${logPrefix} request push stream error:`, error.message);
      });

    let route: string;

    try {
      route = await client.router.route(this.id, host);

      if (pushStream.destroyed) {
        console.debug(`${logPrefix} request push stream closed while routing.`);
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

      pushStream.destroy();

      return;
    }

    console.debug(`${logPrefix} requesting...`);

    let headers = JSON.parse(headersJSON);

    let responded = false;

    let requestResponseStream = this.requestServer(
      id,
      `request-response ${url}`,
      {
        id,
        type: 'request-response',
      },
      {
        endStream: false,
      },
    );

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

        this.requestServer(id, `response-headers ${url}`, {
          id,
          type: 'response-headers',
          status,
          headers: JSON.stringify(headers),
        });

        responded = true;

        proxyResponse.pipe(requestResponseStream);

        proxyResponse
          .on('end', () => {
            console.debug(`${logPrefix} proxy response "end".`);
          })
          .on('close', () => {
            console.debug(`${logPrefix} proxy response "close".`);
            closeOnDrain(requestResponseStream);
          })
          .on('error', error => {
            console.error(`${logPrefix} proxy response error:`, error.message);
          });
      },
    );

    requestResponseStream.pipe(proxyRequest);

    requestResponseStream
      .on('end', () => {
        console.debug(`${logPrefix} request-response stream "end".`);
      })
      .on('close', () => {
        console.debug(`${logPrefix} request-response stream "close".`);
        proxyRequest.destroy();
      })
      .on('error', error => {
        console.error(
          `${logPrefix} request-response stream error:`,
          error.message,
        );
      });

    // Seems that ClientRequest does not have "close" event.
    proxyRequest.on('error', error => {
      console.error(`${logPrefix} proxy request error:`, error.message);
      pushStream.destroy();

      if (responded) {
        return;
      }

      let responseStream: HTTP2.ClientHttp2Stream;

      if ((error as any).code === 'ENOTFOUND') {
        responseStream = this.requestServer(
          id,
          `request-response (404) ${url}`,
          {
            id,
            type: 'request-headers-end',
            status: 404,
          },
        );
      } else {
        responseStream = this.requestServer(
          id,
          `request-response (500) ${url}`,
          {
            id,
            type: 'request-headers-end',
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

    // Debugging logs added at the beginning of `request()`.
    pushStream.on('close', () => {
      if (requestResponseStream) {
        closeOnDrain(requestResponseStream);
      }

      proxyRequest.destroy();
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
