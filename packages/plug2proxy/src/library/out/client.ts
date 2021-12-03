import * as HTTP2 from 'http2';

import _ from 'lodash';

import {Router} from '../router';

import {Session} from './session';

const CREATE_SESSION_DEBOUNCE = 1_000;

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

  private createSessionsDebouncePromise = Promise.resolve();

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

    if (_.pull(sessions, session).length === 0) {
      return;
    }

    console.info(`removed a session, ${sessions.length} remains.`);

    this.createSession();
  }

  private createSession(): void {
    this.createSessionsDebouncePromise =
      this.createSessionsDebouncePromise.then(() => {
        let sessions = this.sessions;

        sessions.push(new Session(this));

        console.info(`new session created, ${sessions.length} in total.`);

        if (sessions.length < this.sessionCandidates) {
          this.createSession();
        }

        return new Promise<void>(resolve =>
          setTimeout(resolve, CREATE_SESSION_DEBOUNCE),
        );
      });
  }
}
