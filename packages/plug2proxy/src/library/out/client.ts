import * as HTTP2 from 'http2';

import _ from 'lodash';

import {BatchScheduler} from '../@utils';
import {Router} from '../router';

import {Session} from './session';

const CREATE_SESSION_DEBOUNCE = 1_000;

const PRINT_ACTIVE_STREAMS_TIME_SPAN = 5_000;

const SESSION_CANDIDATES_DEFAULT = 1;

export interface ClientOptions {
  /**
   * 明文密码（HTTP2 中加密传输）。
   */
  password?: string;
  connect: {
    /**
     * 代理入口服务器，如 "example.com:8001"。
     */
    authority: string;
    options: HTTP2.SecureClientSessionOptions;
  };
  session?: {
    /**
     * 候选连接数量。
     */
    candidates?: number;
  };
}

export class Client {
  private sessions: Session[] = [];

  readonly password: string | undefined;

  readonly connectAuthority: string;
  readonly connectOptions: HTTP2.SecureClientSessionOptions;

  readonly sessionCandidates: number;

  private createSessionScheduler = new BatchScheduler(() => {
    let sessions = this.sessions;

    sessions.push(new Session(this));

    console.info(`new session created, ${sessions.length} in total.`);

    if (sessions.length < this.sessionCandidates) {
      this.createSession();
    }
  }, CREATE_SESSION_DEBOUNCE);

  private activeStreamEntrySet = new Set<ActiveStreamEntry>();

  private printActiveStreamsScheduler = new BatchScheduler(() => {
    console.debug(`active streams of session:`);

    for (let {type, description, session: sessionId, stream} of this
      .activeStreamEntrySet) {
      console.debug(
        `  [${sessionId}:${stream.id ?? '-'}] ${stream.readable ? 'r' : '-'}${
          stream.writable ? 'w' : '-'
        } ${type === 'request' ? '>>>' : '<<<'} ${description}`,
      );
    }
  }, PRINT_ACTIVE_STREAMS_TIME_SPAN);

  constructor(readonly router: Router, readonly options: ClientOptions) {
    let {
      password,
      connect: {authority: connectAuthority, options: connectOptions},
      session: {
        candidates: sessionCandidates = SESSION_CANDIDATES_DEFAULT,
      } = {},
    } = options;

    this.password = password;

    this.connectAuthority = connectAuthority;
    this.connectOptions = connectOptions;

    this.sessionCandidates = sessionCandidates;

    this.createSession();
  }

  removeSession(session: Session): void {
    let sessions = this.sessions;

    let index = sessions.indexOf(session);

    if (index < 0) {
      return;
    }

    sessions.splice(index, 1);

    console.info(`removed a session, ${sessions.length} remains.`);

    this.createSession();
  }

  addActiveStream(
    type: 'request' | 'push',
    description: string,
    sessionId: number,
    stream: HTTP2.ClientHttp2Stream,
  ): void {
    let activeStreamEntrySet = this.activeStreamEntrySet;

    let entry: ActiveStreamEntry = {
      type,
      description,
      session: sessionId,
      stream,
    };

    activeStreamEntrySet.add(entry);

    stream
      .on('ready', () => {
        void this.printActiveStreamsScheduler.schedule();
      })
      .on('close', () => {
        activeStreamEntrySet.delete(entry);
        void this.printActiveStreamsScheduler.schedule();
      })
      .on('error', () => {
        activeStreamEntrySet.delete(entry);
        void this.printActiveStreamsScheduler.schedule();
      });

    void this.printActiveStreamsScheduler.schedule();
  }

  private createSession(): void {
    void this.createSessionScheduler.schedule();
  }
}

interface ActiveStreamEntry {
  type: 'request' | 'push';
  description: string;
  session: number;
  stream: HTTP2.ClientHttp2Stream;
}
