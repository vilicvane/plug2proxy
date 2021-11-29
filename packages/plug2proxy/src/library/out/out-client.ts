import * as TLS from 'tls';

import {debug} from '../debug';
import {Router} from '../router';

import {OutInConnection} from './out-in-connection';

const RETRIEVED_AT_WINDOW = 2_000;
const SCALE_MULTIPLIER = 1;

const IDLE_CONNECTION_SCHEDULE_DELAY = 1_000;

export interface OutClientOptions {
  password?: string;
  server: TLS.ConnectionOptions;
  connections: {
    initial: number;
  };
}

export class OutClient {
  private idleConnectionSet = new Set<OutInConnection>();

  private retrievedAts: number[] = [];

  private idleConnectionScalingTimeout: NodeJS.Timeout | undefined;

  constructor(readonly router: Router, readonly options: OutClientOptions) {
    let {
      connections: {initial},
    } = options;

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

    debug('retrieved idle connection to %s', connection.remoteAddress);

    return connection;
  }

  removeIdleConnection(connection: OutInConnection): void {
    let idleConnectionSet = this.idleConnectionSet;

    idleConnectionSet.delete(connection);

    this.scheduleIdleConnectionScaling();

    debug('removed idle connection to %s', connection.remoteAddress);
  }

  addIdleConnection(connection: OutInConnection): void {
    let idleConnectionSet = this.idleConnectionSet;

    idleConnectionSet.add(connection);

    debug('added idle connection to %s', connection.remoteAddress);
  }

  returnIdleConnection(connection: OutInConnection): void {
    let idleConnectionSet = this.idleConnectionSet;

    connection.idledAt = Date.now();

    idleConnectionSet.add(connection);

    debug('returned idle connection to %s', connection.remoteAddress);
  }

  private scaleIdleConnections(): void {
    if (this.idleConnectionScalingTimeout) {
      clearTimeout(this.idleConnectionScalingTimeout);

      this.idleConnectionScalingTimeout = undefined;
    }

    let {
      connections: {initial},
    } = this.options;

    let idleConnectionSet = this.idleConnectionSet;

    let targetSize = Math.max(
      Math.round(this.retrievedAts.length * SCALE_MULTIPLIER),
      initial,
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
    }, IDLE_CONNECTION_SCHEDULE_DELAY);
  }

  private createIdleConnections(count: number): void {
    let idleConnectionSet = this.idleConnectionSet;

    for (let i = 0; i < count; i++) {
      new OutInConnection(this);
    }

    debug(
      'created %d connection(s), now %d idle in total',
      count,
      idleConnectionSet.size,
    );
  }
}
