import * as Net from 'net';
import * as TLS from 'tls';

import Debug from 'debug';
import _ from 'lodash';

import {InOutPacket} from '../packets';

import {Connection} from './connection';

const debug = Debug('p2p:in:server');

const CONNECTION_PING_PONG_TIMEOUT_DEFAULT = 1000;
const CONNECTION_PING_PONG_INTERVAL_DEFAULT = 5000;
const CONNECTION_CLAIM_ATTEMPTS_DEFAULT = 3;

export interface ServerOptions {
  password?: string;
  listen: Net.ListenOptions;
  tls: TLS.TlsOptions;
  connection?: {
    pingPongTimeout?: number;
    pingPongInterval?: number;
    claimAttempts?: number;
  };
}

export class Server {
  private connections: Connection[] = [];
  private connectionResolvers: ((connection: Connection) => void)[] = [];

  readonly password: string | undefined;
  readonly connectionPingPongTimeout: number;
  readonly connectionPingPongInterval: number;
  readonly connectionClaimAttempts: number;

  readonly tlsServer: TLS.Server;

  constructor({
    password,
    listen: listenOptions,
    tls: tlsOptions,
    connection: {
      pingPongTimeout:
        connectionPingPongTimeout = CONNECTION_PING_PONG_TIMEOUT_DEFAULT,
      pingPongInterval:
        connectionPingPongInterval = CONNECTION_PING_PONG_INTERVAL_DEFAULT,
      claimAttempts:
        connectionClaimAttempts = CONNECTION_CLAIM_ATTEMPTS_DEFAULT,
    } = {},
  }: ServerOptions) {
    this.password = password;
    this.connectionPingPongTimeout = connectionPingPongTimeout;
    this.connectionPingPongInterval = connectionPingPongInterval;
    this.connectionClaimAttempts = connectionClaimAttempts;

    let tlsServer = TLS.createServer(tlsOptions, socket => {
      new Connection(socket, this);
    });

    tlsServer.listen(listenOptions);

    this.tlsServer = tlsServer;
  }

  async claimConnection(packets?: InOutPacket[]): Promise<Connection> {
    let attempts = this.connectionClaimAttempts;

    for (let attempt = 0; attempt < attempts; attempt++) {
      let connection = await this.retrieveConnection();

      connection.setIdle(false);

      try {
        await connection.ping(packets);

        connection.debug('connection claimed');

        return connection;
      } catch (error) {
        connection.debug(
          'claim ping error %e (attempt %d)',
          error,
          attempt + 1,
        );
      }
    }

    throw new Error(`Failed to claim connection after ${attempts} attempt(s)`);
  }

  returnConnection(connection: Connection): void {
    if (connection.idle) {
      debug('trying to return an idle connection');
      return;
    }

    connection.write({
      type: 'return',
    });

    connection.setIdle(true);

    // Mark connection idle but do not push it back.
    // Wait for out-in `ready` to reach a mutual confirmation.
  }

  dropConnection(connection: Connection): void {
    _.pull(this.connections, connection);
    connection.destroy();
  }

  pushConnection(connection: Connection): void {
    let resolver = this.connectionResolvers.shift();

    if (resolver) {
      resolver(connection);
    } else {
      this.connections.push(connection);
    }
  }

  private async retrieveConnection(): Promise<Connection> {
    let connections = this.connections;

    let connection =
      connections.length > 0
        ? connections.splice(_.random(connections.length - 1), 1)[0]
        : undefined;

    if (!connection) {
      connection = await new Promise<Connection>(resolve => {
        this.connectionResolvers.push(resolve);
      });
    }

    return connection;
  }
}
