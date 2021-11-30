import * as HTTP from 'http';
import * as Net from 'net';
import * as TLS from 'tls';

import Debug from 'debug';
import {StreamJet} from 'socket-jet';

import {
  HOP_BY_HOP_HEADERS_REGEX,
  pipeBufferStreamToJet,
  pipeJetToBufferStream,
} from '../@common';
import {groupRawHeaders} from '../@utils';
import {
  InOutConnectOptions,
  InOutPacket,
  InOutRequestOptions,
  OutInPacket,
} from '../packets';
import {InRoute} from '../types';

import {Client} from './client';

const debug = Debug('p2p:out:connection');

export class Connection extends StreamJet<
  InOutPacket,
  OutInPacket,
  TLS.TLSSocket
> {
  private id: string;

  remoteAddress: string | undefined;

  idledAt: number;

  readonly client: Client;

  private stage: 'wait-for-connect' | 'ready' | 'busy' | 'removed';

  lastAction: string | undefined;

  constructor(client: Client) {
    let socket = TLS.connect(client.connectOptions);

    super(socket);

    this.id = (++Connection.lastId).toString();

    this.idledAt = Infinity;
    this.stage = 'wait-for-connect';

    this.debug(
      'set initial socket timeout %d',
      client.connectionInitialPingTimeout,
    );

    socket.setTimeout(client.connectionInitialPingTimeout);

    socket
      .on('timeout', () => {
        this.debug('socket timed out');
        socket.end();
      })
      .on('secureConnect', () => {
        this.remoteAddress = socket.remoteAddress;
        this.stage = 'ready';

        this.write({
          type: 'ready',
          id: this.id,
          password: client.password,
        });

        this.add();
      });

    this.on('data', packet => {
      switch (packet.type) {
        case 'ping':
          this.write({
            type: 'pong',
            timestamp: packet.timestamp,
          });

          if (packet.span) {
            this.debug('set socket timeout %d', packet.span);
            socket.setTimeout(packet.span);
          }

          break;
        case 'return':
          this.return();
          break;
        case 'connect':
          void this.connect(packet.options);
          break;
        case 'request':
          void this.request(packet.options);
          break;
        case 'route':
          void this.route(packet.host);
          break;
        case 'error':
          console.info('in-out connection error', packet.code);
          break;
        default:
          break;
      }
    })
      .on('close', () => {
        this.debug('connection close');
        // Redundancy.
        this.remove();
      })
      .on('end', () => {
        this.debug('connection end');
        this.remove();
      })
      .on('error', error => {
        this.debug('connection error %e', error);
        this.remove();
      });

    this.client = client;
  }

  debug(format: string, ...args: any[]): void {
    debug(`[%s] ${format}`, this.id, ...args);
  }

  private async connect(options: InOutConnectOptions): Promise<void> {
    let client = this.client;

    let {host, port} = options;

    this.lastAction = `connect ${host}:${port}`;

    this.debug('connect %s:%d', host, port);

    this.retrieve();

    let route: string;

    try {
      route = await client.router.route(host!);
    } catch (error: any) {
      this.debug('route error %s %e', host, error);
      route = 'direct';
    }

    this.debug('routed %s %s', route, host);

    if (route === 'direct') {
      this.write({
        type: 'connection-direct',
      });

      return;
    }

    this.debug('connecting %s:%d', host, port);

    let outSocket = Net.createConnection(options);

    let connectionEstablished = false;

    outSocket
      .on('connect', () => {
        connectionEstablished = true;

        this.debug('connected %s:%d', host, port);

        this.write({
          type: 'connection-established',
        });

        pipeBufferStreamToJet(outSocket, this);
        pipeJetToBufferStream(this, outSocket);

        outSocket.on('end', () => {
          this.debug('out socket end');
        });

        outSocket.on('close', () => {
          this.debug('out socket close');
        });
      })
      .on('error', error => {
        this.debug('out socket error %e', error);

        if (connectionEstablished) {
          this.write({
            type: 'stream-end',
          });
        } else {
          this.write({
            type: 'connection-error',
          });
        }
      });
  }

  private async request({url, ...options}: InOutRequestOptions): Promise<void> {
    let {method} = options;

    this.lastAction = `request ${method} ${url}`;

    this.debug('request %s %s', method, url);

    this.retrieve();

    let responded = false;

    let request = HTTP.request(url, options, response => {
      let status = response.statusCode!;

      this.debug('response %s %s %d', status);

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

      this.write({
        type: 'request-response',
        status,
        headers,
      });

      responded = true;

      pipeBufferStreamToJet(response, this);
    });

    pipeJetToBufferStream(this, request);

    request.on('error', (error: any) => {
      this.debug('request error %s', error.code ?? error.message);

      if (!responded) {
        if (error.code === 'ENOTFOUND') {
          this.write({
            type: 'request-response',
            status: 404,
          });
        } else {
          this.write({
            type: 'request-response',
            status: 500,
          });
        }
      }
    });
  }

  private async route(host: string): Promise<void> {
    this.lastAction = `route ${host}`;

    this.retrieve();

    let sourceRoute = await this.client.router.route(host!);
    let route: InRoute = sourceRoute === 'direct' ? 'direct' : 'proxy';

    debug('routed %s %s', route, host);

    this.write({
      type: 'route-result',
      route,
    });
  }

  private retrieve(): void {
    if (this.stage === 'busy') {
      return;
    }

    this.stage = 'busy';
    this.idledAt = Infinity;

    this.client.retrieveIdleConnection(this);
  }

  private add(): void {
    this.client.addIdleConnection(this);
  }

  private return(): void {
    this.write({
      type: 'ready',
    });

    this.stage = 'ready';
    this.idledAt = Date.now();

    this.client.returnIdleConnection(this);
  }

  private remove(): void {
    this.stage = 'removed';
    this.client.removeConnection(this);
  }

  private static lastId = 0;
}
