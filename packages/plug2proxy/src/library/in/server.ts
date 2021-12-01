import * as Net from 'net';
import * as TLS from 'tls';

import Debug from 'debug';
import _ from 'lodash';

import {InOutPacket} from '../packets';

import {Connection} from './connection';

const debug = Debug('p2p:in:server');

const CONNECTION_PING_PONG_TIMEOUT_DEFAULT = 1000;
const CONNECTION_PING_PONG_INTERVAL_DEFAULT = 30_000;
const CONNECTION_CLAIM_PING_DEFAULT = true;
const CONNECTION_CLAIM_PING_ATTEMPTS_DEFAULT = 3;

export interface ServerOptions {
  /**
   * 明文密码（TLS 中传输）。
   */
  password?: string;
  /**
   * 监听选项，供代理出口连接（注意此端口通常需要在防火墙中允许）。如：
   *
   * ```json
   * {
   *   "port": 8001
   * }
   * ```
   */
  listen: Net.ListenOptions;
  /**
   * TLS 选项，配置证书等。如：
   *
   * ```json
   * {
   *   "cert": "-----BEGIN CERTIFICATE-----\n[...]\n-----END CERTIFICATE-----",
   *   "key": "-----BEGIN PRIVATE KEY-----\n[...]\n-----END PRIVATE KEY-----",
   * }
   * ```
   */
  tls: TLS.TlsOptions;
  connection?: {
    /**
     * ping/pong 超时时间。
     */
    pingPongTimeout?: number;
    /**
     * ping/pong 间隔时间。
     */
    pingPongInterval?: number;
    /**
     * 是否在获取建立连接时进行一次 ping/pong。
     */
    claimPing?: boolean;
    /**
     * 建立连接时进行 ping/pong 的尝试次数，每次都会换一个连接。
     */
    claimPingAttempts?: number;
  };
}

export class Server {
  private connections: Connection[] = [];
  private connectionResolvers: ((connection: Connection) => void)[] = [];

  readonly password: string | undefined;
  readonly connectionPingPongTimeout: number;
  readonly connectionPingPongInterval: number;
  readonly connectionClaimPing: boolean;
  readonly connectionClaimPingAttempts: number;

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
      claimPing: connectionClaimPing = CONNECTION_CLAIM_PING_DEFAULT,
      claimPingAttempts:
        connectionClaimPingAttempts = CONNECTION_CLAIM_PING_ATTEMPTS_DEFAULT,
    } = {},
  }: ServerOptions) {
    this.password = password;
    this.connectionPingPongTimeout = connectionPingPongTimeout;
    this.connectionPingPongInterval = connectionPingPongInterval;
    this.connectionClaimPing = connectionClaimPing;
    this.connectionClaimPingAttempts = connectionClaimPingAttempts;

    let tlsServer = TLS.createServer(tlsOptions, socket => {
      new Connection(socket, this);
    });

    tlsServer.listen(listenOptions);

    this.tlsServer = tlsServer;
  }

  async claimConnection(packets: InOutPacket[] = []): Promise<Connection> {
    if (this.connectionClaimPing) {
      let attempts = this.connectionClaimPingAttempts;

      for (let attempt = 0; attempt < attempts; attempt++) {
        let connection = await this.retrieveConnection();

        connection.setIdle(false);

        let okay = await connection.ping(packets, undefined, true);

        if (okay) {
          connection.debug('connection claimed');
          return connection;
        } else {
          connection.debug('claim ping failed (attempt %d)', attempt + 1);
        }
      }

      throw new Error(
        `Failed to claim connection after ${attempts} attempt(s)`,
      );
    } else {
      let connection = await this.retrieveConnection();

      connection.setIdle(false);

      connection.pause();

      for (let packet of packets) {
        connection.write(packet);
      }

      return connection;
    }
  }

  returnConnection(connection: Connection): void {
    if (!connection.writable) {
      connection.debug('tried to return a finished connection');
      return;
    }

    if (connection.idle) {
      connection.debug('tried to return an idle connection');
      return;
    }

    if (connection.isPaused()) {
      connection.debug('trying to return a paused connection');
      connection.resume();
    }

    connection.debug('return connection');

    connection.write({
      type: 'return',
    });

    connection.setIdle(true);

    // Mark connection idle but do not push it back.
    // Wait for out-in `ready` to reach a mutual confirmation.
  }

  dropConnection(connection: Connection): void {
    _.pull(this.connections, connection);

    if (connection.writable) {
      connection.end();
    }
  }

  pushConnection(connection: Connection): void {
    let resolver = this.connectionResolvers.shift();

    if (resolver) {
      resolver(connection);
    } else {
      this.connections.push(connection);
    }

    connection.debug('connection pushed');
  }

  private async retrieveConnection(): Promise<Connection> {
    let connections = this.connections;

    debug('retrieve connection, %d available', connections.length);

    if (connections.length > 0) {
      let connection = _.minBy(connections, connection => connection.latency)!;

      _.pull(connections, connection);

      return connection;
    } else {
      return new Promise<Connection>(resolve => {
        this.connectionResolvers.push(resolve);
      });
    }
  }
}
