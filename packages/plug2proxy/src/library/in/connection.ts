import * as Net from 'net';

import Debug from 'debug';
import {StreamJet} from 'socket-jet';

import {refEventEmitter, timeout} from '../@utils';
import {InOutPacket, OutInPacket} from '../packets';

import {Server} from './server';

const debug = Debug('p2p:in:connection');

const EXPECTED_PING_SPAN_MULTIPLIER = 2;

export class Connection extends StreamJet<
  OutInPacket,
  InOutPacket,
  Net.Socket
> {
  private _id = (++Connection.lastId).toString();

  private _idle = true;
  private _authorized = false;

  latency = Infinity;

  constructor(socket: Net.Socket, readonly server: Server) {
    super(socket);

    socket.setTimeout(server.connectionPingPongInterval);

    socket.on('timeout', () => {
      void this.ping();
    });

    this.on('data', packet => {
      if (packet.type !== 'ready') {
        return;
      }

      let authorized = this._authorized;

      if (!authorized) {
        authorized = packet.password === server.password;

        if (!authorized) {
          this.debug('authorize failed: wrong password');

          this.end({
            type: 'error',
            code: 'WRONG_PASSWORD',
          });

          return;
        }

        this._authorized = authorized;
      }

      if (!this.idle) {
        this.debug('unexpected ready packet for non-idle connection');

        this.end({
          type: 'error',
          code: 'CONNECTION_NOT_IDLE',
        });

        return;
      }

      if (packet.id) {
        this._id += `<-${packet.id}`;

        void this.ping(
          [],
          server.connectionPingPongInterval * EXPECTED_PING_SPAN_MULTIPLIER,
        );
      }

      server.pushConnection(this);
    })
      .on('close', () => {
        this.debug('connection close');
        server.dropConnection(this);
      })
      .on('end', () => {
        this.debug('connection close');
        server.dropConnection(this);
      })
      .on('error', error => {
        this.debug('connection error %e', error);
        server.dropConnection(this);
      });
  }

  get id(): string {
    return this._id;
  }

  get idle(): boolean {
    return this._idle;
  }

  get authorized(): boolean {
    return this._authorized;
  }

  /**
   * @param packets Packets to send immediately after ping (so that it does not
   * wait for pong.
   * @param span With in which time span should the other side expect another
   * ping.
   */
  async ping(
    packets: InOutPacket[] = [],
    span?: number,
    toPause = false,
  ): Promise<boolean> {
    if (!this.writable) {
      this.debug('ping ignored');
      return false;
    }

    const server = this.server;

    let timestamp = Date.now();

    this.write({
      type: 'ping',
      timestamp,
      span,
    });

    for (let packet of packets) {
      this.write(packet);
    }

    let pingPongEventSession = refEventEmitter(this);

    try {
      await timeout(
        new Promise<void>((resolve, reject) => {
          pingPongEventSession
            .on('data', (packet: OutInPacket) => {
              if (packet.type !== 'pong') {
                return;
              }

              if (packet.timestamp === timestamp) {
                if (toPause) {
                  this.pause();
                }

                this.latency = Date.now() - timestamp;

                resolve();
              } else {
                this.debug(
                  'received mismatched pong %d (%d)',
                  packet.timestamp,
                  timestamp,
                );
              }
            })
            .once('close', resolve)
            .once('error', reject);
        }),
        server.connectionPingPongTimeout,
      );
    } catch (error) {
      this.debug('ping error %e', error);
      server.dropConnection(this);

      return false;
    } finally {
      pingPongEventSession.end();
    }

    return true;
  }

  setIdle(idle: boolean): void {
    this._idle = idle;
  }

  debug(format: string, ...args: any[]): void {
    debug(`[%s] ${format}`, this.id, ...args);
  }

  private static lastId = 0;
}
