import type * as HTTP2 from 'http2';

import _ from 'lodash';
import * as x from 'x-value';

import {BatchScheduler} from '../@utils';
import type {Router} from '../router';

import {Session} from './session';

const CREATE_SESSION_DEBOUNCE = 1_000;

const PRINT_ACTIVE_STREAMS_TIME_SPAN = 5_000;

const SESSION_CANDIDATES_DEFAULT = 1;

export const ClientOptions = x.object({
  /**
   * 明文密码（HTTP2 中加密传输）。
   */
  password: x.string.optional(),
  connect: x.object({
    /**
     * 代理入口服务器，如 "example.com:8443"。
     */
    authority: x.string,
    options: x
      .object({
        rejectUnauthorized: x.boolean.optional(),
      })
      .optional(),
  }),
  session: x
    .object({
      /**
       * 候选连接数量。
       */
      candidates: x.number.optional(),
    })
    .optional(),
});

export type ClientOptions = x.TypeOf<typeof ClientOptions>;

export class Client {
  private sessions: Session[] = [];

  readonly password: string | undefined;

  readonly connectAuthority: string;
  readonly connectOptions: HTTP2.SecureClientSessionOptions;

  readonly sessionCandidates: number;

  private createSessionScheduler = new BatchScheduler(() => {
    let sessions = this.sessions;

    sessions.push(new Session(this));

    console.info(
      `(${this.id}) new session created, ${sessions.length} in total.`,
    );

    if (sessions.length < this.sessionCandidates) {
      this.scheduleSessionCreation();
    }
  }, CREATE_SESSION_DEBOUNCE);

  private activeStreamEntrySet = new Set<ActiveStreamEntry>();

  private printActiveStreamsScheduler = new BatchScheduler(() => {
    let activeStreamEntrySet = this.activeStreamEntrySet;

    if (activeStreamEntrySet.size === 0) {
      return;
    }

    console.debug();
    console.debug(`(${this.id})[session:push(stream)] read/write in/out name`);

    for (let {type, description, id, stream} of activeStreamEntrySet) {
      console.debug(
        `  [${id}(${stream.id})] ${stream.readable ? 'r' : '-'}${
          stream.writable ? 'w' : '-'
        } ${type === 'request' ? '>>>' : '<<<'} ${description}`,
      );
    }

    console.debug();
  }, PRINT_ACTIVE_STREAMS_TIME_SPAN);

  constructor(
    readonly router: Router,
    readonly options: ClientOptions,
    readonly id = '-',
  ) {
    let {
      password,
      connect: {authority: connectAuthority, options: connectOptions = {}},
      session: {
        candidates: sessionCandidates = SESSION_CANDIDATES_DEFAULT,
      } = {},
    } = options;

    this.password = password;

    this.connectAuthority = connectAuthority;
    this.connectOptions = connectOptions;

    this.sessionCandidates = sessionCandidates;

    console.info(`(${id}) new client (authority ${this.connectAuthority}).`);

    this.scheduleSessionCreation();
  }

  removeSession(session: Session): void {
    let sessions = this.sessions;

    let index = sessions.indexOf(session);

    if (index < 0) {
      return;
    }

    sessions.splice(index, 1);

    console.info(`(${this.id}) removed 1 session, ${sessions.length} remains.`);

    this.scheduleSessionCreation();
  }

  addActiveStream(
    type: 'request' | 'push',
    description: string,
    id: string,
    stream: HTTP2.ClientHttp2Stream,
  ): void {
    let activeStreamEntrySet = this.activeStreamEntrySet;

    let entry: ActiveStreamEntry = {
      type,
      description,
      id,
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
      });

    void this.printActiveStreamsScheduler.schedule();
  }

  private scheduleSessionCreation(): void {
    void this.createSessionScheduler.schedule();
  }
}

interface ActiveStreamEntry {
  type: 'request' | 'push';
  description: string;
  id: string;
  stream: HTTP2.ClientHttp2Stream;
}
