import * as HTTP from 'http';
import * as Net from 'net';
import * as TLS from 'tls';

import {StreamJet} from 'socket-jet';

import {
  HOP_BY_HOP_HEADERS_REGEX,
  pipeBufferStreamToJet,
  pipeJetToBufferStream,
} from '../@common';
import {groupRawHeaders} from '../@utils';
import {debug, debugConnect, debugRequest} from '../debug';
import {
  InOutConnectOptions,
  InOutData,
  InOutRequestOptions,
  OutInData,
} from '../types';

import {OutClient} from './out-client';

export interface OutInConnectionOptions {
  server: TLS.ConnectionOptions;
}

export class OutInConnection {
  readonly socket: Net.Socket;

  readonly jet: OutInJet;

  idledAt = Date.now();

  remoteAddress = '(unknown)';

  constructor(private client: OutClient) {
    let {server: options, password} = client.options;

    if (options.host) {
      this.remoteAddress = options.host;
    }

    let socket = TLS.connect(options, () => {
      if (socket.remoteAddress) {
        this.remoteAddress = socket.remoteAddress;
      }

      debug('out-in connection to %s established', this.remoteAddress);

      jet.write({
        type: 'initialize',
        password,
      });
    });

    socket.on('error', error => {
      debug(
        'out-in connection to %s error %s',
        this.remoteAddress,
        (error as any).code ?? error.message,
      );

      this.remove();
    });

    socket.on('close', () => {
      debug('out-in connection to %s closed', this.remoteAddress);

      this.remove();
    });

    socket.on('end', () => {
      debug('out-in connection to %s ended', this.remoteAddress);
    });

    this.socket = socket;

    let jet = new StreamJet<InOutData, OutInData, Net.Socket>(socket, {
      heartbeat: true,
    });

    jet.on('error', error => {
      debug(
        'out-in connection to %s error: %s',
        this.remoteAddress,
        (error as any).code ?? error.message,
      );

      this.remove();
    });

    jet.on('data', data => {
      switch (data.type) {
        case 'connect':
          this.connect(data.options).catch(() => {
            socket.destroy();
          });
          break;
        case 'request':
          this.request(data.options).catch(() => {
            socket.destroy();
          });
          break;
        case 'route':
          this.route(data.host).catch(() => {
            socket.destroy();
          });
          break;
        case 'error':
          throw new Error(data.message);
      }
    });

    this.jet = jet;

    client.addIdleConnection(this);
  }

  private async connect(options: InOutConnectOptions): Promise<void> {
    let client = this.client;
    let jet = this.jet;

    let {host, port} = options;

    debugConnect('connect %s:%d', host, port);

    this.retrieve();

    let route = await client.router.route(host!);

    debugConnect('routed %s %s', route, host);

    if (route === 'direct') {
      jet.write({type: 'direct'});

      this.return();

      return;
    }

    debugConnect('connecting %s:%d', host, port);

    let outSocket = Net.createConnection(options, () => {
      debugConnect('connected %s:%d', host, port);

      jet.write({type: 'connected'});

      pipeBufferStreamToJet(outSocket, jet);
      pipeJetToBufferStream(jet, outSocket);

      // outSocket.on('close', () => {
      //   debugConnect('connection closed %s:%d', host, port);
      // });

      outSocket.on('end', () => {
        debugConnect('connection ended %s:%d', host, port);

        jet.write({
          type: 'stream-end',
        });

        this.return();
      });
    });

    outSocket.on('error', error => {
      debugConnect('connection error %s', (error as any).code ?? error.message);

      jet.write({
        type: 'stream-end',
      });

      this.return();
    });
  }

  private async request({url, ...options}: InOutRequestOptions): Promise<void> {
    let {method} = options;

    debugRequest('request %s %s', method, url);

    this.retrieve();

    let jet = this.jet;

    let responded = false;

    let request = HTTP.request(url, options, response => {
      let status = response.statusCode!;

      debugRequest('response %s %s %d', status);

      let headers: {[key: string]: string | string[]} = {};

      for (let [key, value] of groupRawHeaders(response.rawHeaders)) {
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

      jet.write({
        type: 'response',
        status,
        headers,
      });

      responded = true;

      pipeBufferStreamToJet(response, jet);

      response.on('end', () => {
        debugRequest('response ended %s %s', method, url);

        jet.write({
          type: 'stream-end',
        });

        this.return();
      });

      response.on('error', () => {
        debugRequest('response error %s %s', method, url);

        jet.write({
          type: 'stream-end',
        });

        this.return();
      });
    });

    pipeJetToBufferStream(jet, request);

    request.on('error', (error: any) => {
      debugRequest('request error %s', error.code ?? error.message);

      if (!responded) {
        if (error.code === 'ENOTFOUND') {
          jet.write({
            type: 'response',
            status: 404,
          });
        } else {
          jet.write({
            type: 'response',
            status: 500,
          });
        }
      }

      jet.write({
        type: 'stream-end',
      });

      this.return();
    });

    jet.socket.once('close', () => {
      debugRequest('in socket closed %s', url);

      // if the client closes the connection prematurely,
      // then close the upstream socket

      request.destroy();
    });
  }

  private async route(host: string): Promise<void> {
    let jet = this.jet;

    this.retrieve();

    let route = await this.client.router.route(host!);

    if (route === 'direct') {
      debug('routed direct %s', host);
      jet.write({type: 'route-result', route: 'direct'});
    } else {
      debug('routed proxy %s', host);
      jet.write({type: 'route-result', route: 'proxy'});
    }

    this.return();
  }

  private retrieve(): void {
    this.client.retrieveIdleConnection(this);
  }

  private return(): void {
    this.jet.write({
      type: 'initialize',
    });

    this.client.returnIdleConnection(this);
  }

  private remove(): void {
    this.client.removeIdleConnection(this);
  }
}

export type OutInJet = StreamJet<InOutData, OutInData, Net.Socket>;
