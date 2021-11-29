import * as TLS from 'tls';

import {debug} from '../debug';
import {Router} from '../router';

import {OutInConnection} from './out-in-connection';

const RETRIEVED_AT_WINDOW = 2_000;

const IDLE_CONNECTION_SCALING_SCHEDULE_DELAY = 1_000;

const INITIAL_CONNECTIONS_DEFAULT = 2;
const IDLE_SCALE_MULTIPLIER_DEFAULT = 1;
const IDLE_MAX_CONNECTIONS_DEFAULT = 20;

export interface OutClientOptions {
  password?: string;
  server: TLS.ConnectionOptions;
  connections?: {
    initial?: number;
    idleScaleMultiplier?: number;
    idleMax?: number;
  };
}

export class OutClient {
  private idleConnectionSet = new Set<OutInConnection>();

  private retrievedAts: number[] = [];

  private idleConnectionScalingTimeout: NodeJS.Timeout | undefined;

  private initialConnections: number;
  private idleMaxConnections: number;
  private idleScaleMultiplier: number;

  constructor(readonly router: Router, readonly options: OutClientOptions) {
    let {
      connections: {
        initial = INITIAL_CONNECTIONS_DEFAULT,
        idleScaleMultiplier = IDLE_SCALE_MULTIPLIER_DEFAULT,
        idleMax = IDLE_MAX_CONNECTIONS_DEFAULT,
      } = {},
    } = options;

    this.initialConnections = initial;
    this.idleMaxConnections = idleMax;
    this.idleScaleMultiplier = idleScaleMultiplier;

    this.createIdleConnections(initial);
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

    debug(
      'removed idle connection to %s, now %d idle in total',
      connection.remoteAddress,
      idleConnectionSet.size,
    );

    this.scheduleIdleConnectionScaling();
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

    let targetSize = Math.min(
      Math.max(
        Math.round(this.retrievedAts.length * this.idleScaleMultiplier),
        this.initialConnections,
      ),
      this.idleMaxConnections,
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

    if (this.idleConnectionSet.size > 0) {
      this.idleConnectionScalingTimeout = setTimeout(() => {
        this.scaleIdleConnections();
      }, IDLE_CONNECTION_SCALING_SCHEDULE_DELAY);
    } else {
      this.scaleIdleConnections();
    }
  }

  private createIdleConnections(count: number): void {
    for (let i = 0; i < count; i++) {
      new OutInConnection(this);
    }
  }
}
