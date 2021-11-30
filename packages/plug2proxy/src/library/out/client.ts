import * as TLS from 'tls';

import Debug from 'debug';

import {Router} from '../router';

import {Connection} from './connection';

const debug = Debug('p2p:out:client');

const RETRIEVED_AT_WINDOW = 2_000;

const MAX_IDLE_DURATION = 5 * 60_000;

const IDLE_CONNECTION_SCALING_SCHEDULE_DELAY = 1_000;
const IDLE_CONNECTION_CLEAN_UP_SCHEDULE_INTERVAL = 10_000;

const CONNECTION_INITIAL_PING_TIMEOUT_DEFAULT = 1_000;
const CONNECTION_IDLE_MIN_DEFAULT = 5;
const CONNECTION_IDLE_MAX_DEFAULT = 50;
const CONNECTION_IDLE_SCALE_MULTIPLIER_DEFAULT = 1;

export interface ClientOptions {
  /**
   * 明文密码（TLS 中传输）。
   */
  password?: string;
  /**
   * 代理入口服务器连接选项。如：
   *
   * ```json
   * {
   *   "host": "example.com",
   *   "port": 8001
   * }
   * ```
   */
  connect: TLS.ConnectionOptions;
  connection?: {
    initialPingTimeout?: number;
    idleMin?: number;
    idleMax?: number;
    idleScaleMultiplier?: number;
  };
}

export class Client {
  private idleConnectionSet = new Set<Connection>();

  private retrievedAts: number[] = [];

  private idleConnectionScalingTimeout: NodeJS.Timeout | undefined;

  readonly password: string | undefined;
  readonly connectOptions: TLS.ConnectionOptions;
  readonly connectionInitialPingTimeout: number;
  readonly connectionIdleMin: number;
  readonly connectionIdleMax: number;
  readonly connectionIdleScaleMultiplier: number;

  constructor(readonly router: Router, readonly options: ClientOptions) {
    let {
      password,
      connect: connectOptions,
      connection: {
        initialPingTimeout:
          connectionInitialPingTimeout = CONNECTION_INITIAL_PING_TIMEOUT_DEFAULT,
        idleMin: connectionIdleMin = CONNECTION_IDLE_MIN_DEFAULT,
        idleMax: connectionIdleMax = CONNECTION_IDLE_MAX_DEFAULT,
        idleScaleMultiplier:
          connectionIdleScaleMultiplier = CONNECTION_IDLE_SCALE_MULTIPLIER_DEFAULT,
      } = {},
    } = options;

    this.password = password;
    this.connectOptions = connectOptions;
    this.connectionInitialPingTimeout = connectionInitialPingTimeout;
    this.connectionIdleMin = connectionIdleMin;
    this.connectionIdleMax = connectionIdleMax;
    this.connectionIdleScaleMultiplier = connectionIdleScaleMultiplier;

    this.createIdleConnections(connectionIdleMin);

    setInterval(() => {
      this.cleanUpIdleConnections();
    }, IDLE_CONNECTION_CLEAN_UP_SCHEDULE_INTERVAL);
  }

  retrieveIdleConnection(connection: Connection): Connection {
    let now = Date.now();

    let idleConnectionSet = this.idleConnectionSet;

    idleConnectionSet.delete(connection);

    let retrievedAts = this.retrievedAts;

    retrievedAts.push(now);

    while (retrievedAts[0] + RETRIEVED_AT_WINDOW < now) {
      retrievedAts.shift();
    }

    this.scaleIdleConnections();

    debug(
      'retrieved idle connection to %s, now %d idle in total',
      connection.remoteAddress,
      idleConnectionSet.size,
    );

    return connection;
  }

  removeIdleConnection(connection: Connection): void {
    let idleConnectionSet = this.idleConnectionSet;

    idleConnectionSet.delete(connection);

    debug(
      'removed idle connection to %s, now %d idle in total',
      connection.remoteAddress,
      idleConnectionSet.size,
    );

    this.scheduleIdleConnectionScaling();
  }

  addIdleConnection(connection: Connection): void {
    let idleConnectionSet = this.idleConnectionSet;

    idleConnectionSet.add(connection);

    debug(
      'added idle connection to %s, now %d idle in total',
      connection.remoteAddress,
      idleConnectionSet.size,
    );
  }

  returnIdleConnection(connection: Connection): void {
    let idleConnectionSet = this.idleConnectionSet;

    idleConnectionSet.add(connection);

    debug(
      'returned idle connection to %s, now %d idle in total',
      connection.remoteAddress,
      idleConnectionSet.size,
    );
  }

  private scaleIdleConnections(): void {
    if (this.idleConnectionScalingTimeout) {
      clearTimeout(this.idleConnectionScalingTimeout);

      this.idleConnectionScalingTimeout = undefined;
    }

    let idleConnectionSet = this.idleConnectionSet;

    let targetSize = Math.min(
      Math.max(
        Math.round(
          this.retrievedAts.length * this.connectionIdleScaleMultiplier,
        ),
        this.connectionIdleMin,
      ),
      this.connectionIdleMax,
    );

    let deficiency = targetSize - idleConnectionSet.size;

    if (deficiency > 0) {
      this.createIdleConnections(deficiency);
    } else {
      debug(
        'skipped idle connection scaling, now %d idle in total',
        idleConnectionSet.size,
      );
    }
  }

  private scheduleIdleConnectionScaling(): void {
    if (this.idleConnectionScalingTimeout) {
      clearTimeout(this.idleConnectionScalingTimeout);
    }

    this.idleConnectionScalingTimeout = setTimeout(() => {
      this.scaleIdleConnections();
    }, IDLE_CONNECTION_SCALING_SCHEDULE_DELAY);
  }

  private cleanUpIdleConnections(): void {
    let now = Date.now();

    for (let connection of this.idleConnectionSet) {
      if (now - connection.idledAt > MAX_IDLE_DURATION) {
        connection.end();
      }
    }

    this.scaleIdleConnections();
  }

  private createIdleConnections(count: number): void {
    for (let i = 0; i < count; i++) {
      new Connection(this);
    }
  }
}
