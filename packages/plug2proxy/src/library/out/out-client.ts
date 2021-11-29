import * as TLS from 'tls';

import {debug} from '../debug';
import {Router} from '../router';

import {OutInConnection} from './out-in-connection';

const RETRIEVED_AT_WINDOW = 2_000;

const MAX_IDLE_DURATION = 2 * 60_000;

const IDLE_CONNECTION_SCALING_SCHEDULE_DELAY = 1_000;
const IDLE_CONNECTION_CLEAN_UP_SCHEDULE_DELAY = 10_000;

const INITIAL_CONNECTIONS_DEFAULT = 2;
const SCALE_MULTIPLIER_DEFAULT = 1;

export interface OutClientOptions {
  password?: string;
  server: TLS.ConnectionOptions;
  connections?: {
    initial?: number;
    scaleMultiplier?: number;
  };
}

export class OutClient {
  private idleConnectionSet = new Set<OutInConnection>();

  private retrievedAts: number[] = [];

  private idleConnectionScalingTimeout: NodeJS.Timeout | undefined;
  private idleConnectionCleanUpTimeout: NodeJS.Timeout | undefined;

  private initialConnections: number;
  private scaleMultiplier: number;

  constructor(readonly router: Router, readonly options: OutClientOptions) {
    let {
      connections: {
        initial = INITIAL_CONNECTIONS_DEFAULT,
        scaleMultiplier = SCALE_MULTIPLIER_DEFAULT,
      } = {},
    } = options;

    this.initialConnections = initial;
    this.scaleMultiplier = scaleMultiplier;

    this.createIdleConnections(initial);

    setInterval(() => {
      let now = Date.now();

      for (let connection of this.idleConnectionSet) {
        if (now - connection.idledAt > MAX_IDLE_DURATION) {
        }
      }
    }, MAX_IDLE_DURATION / 2);
  }

  retrieveIdleConnection(connection: OutInConnection): OutInConnection {
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

  removeIdleConnection(connection: OutInConnection): void {
    let idleConnectionSet = this.idleConnectionSet;

    idleConnectionSet.delete(connection);

    this.scheduleIdleConnectionScaling();

    debug(
      'removed idle connection to %s, now %d idle in total',
      connection.remoteAddress,
      idleConnectionSet.size,
    );
  }

  addIdleConnection(connection: OutInConnection): void {
    let idleConnectionSet = this.idleConnectionSet;

    idleConnectionSet.add(connection);

    debug(
      'added idle connection to %s, now %d idle in total',
      connection.remoteAddress,
      idleConnectionSet.size,
    );
  }

  returnIdleConnection(connection: OutInConnection): void {
    let idleConnectionSet = this.idleConnectionSet;

    connection.idledAt = Date.now();

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

    let targetSize = Math.max(
      Math.round(this.retrievedAts.length * this.scaleMultiplier),
      this.initialConnections,
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

    this.cleanUpIdleConnections();
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
        connection.socket.destroy();
      }
    }

    this.scheduleIdleConnectionCleanUp();
  }

  private scheduleIdleConnectionCleanUp(): void {
    if (this.idleConnectionCleanUpTimeout) {
      clearTimeout(this.idleConnectionCleanUpTimeout);
    }

    this.idleConnectionCleanUpTimeout = setTimeout(() => {
      this.cleanUpIdleConnections();
    }, IDLE_CONNECTION_CLEAN_UP_SCHEDULE_DELAY);
  }

  private createIdleConnections(count: number): void {
    for (let i = 0; i < count; i++) {
      new OutInConnection(this);
    }
  }
}
