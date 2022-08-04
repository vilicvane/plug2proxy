import * as FS from 'fs';
import * as HTTP2 from 'http2';
import * as Path from 'path';

import bytes from 'bytes';
import _ from 'lodash';
import ms from 'ms';
import * as x from 'x-value';
import * as xn from 'x-value/node';

import {IPPattern, Port} from '../@x-types';

const SESSION_PING_INTERVAL = ms('5s');
const SESSION_MAX_OUTSTANDING_PINGS = 2;

const WINDOW_SIZE = bytes('32MB');

const LISTEN_HOST_DEFAULT = IPPattern.nominalize('0.0.0.0');
const LISTEN_PORT_DEFAULT = Port.nominalize(8443);

const CERTS_DIR = Path.join(__dirname, '../../../certs');

export const ServerOptions = x.object({
  host: IPPattern.optional(),
  port: Port.optional(),
  cert: x.union(x.string, xn.Buffer).optional(),
  key: x.union(x.string, xn.Buffer).optional(),
  password: x.string.optional(),
});

export type ServerOptions = x.TypeOf<typeof ServerOptions>;

export class Server {
  private sessionToSessionCandidateMap = new Map<
    HTTP2.Http2Session,
    SessionCandidate
  >();

  private sessionCandidateResolvers: ((candidate: SessionCandidate) => void)[] =
    [];

  // private activeSessionCandidates: readonly SessionCandidate[] = [];

  // private prioritizedSessionCandidatesRef = this.activeSessionCandidates;
  // private prioritizedSessionCandidates: SessionCandidate[] = [];

  readonly password: string | undefined;

  readonly http2SecureServer: HTTP2.Http2SecureServer;

  private streamListenerMap = new Map<string, ServerStreamListener>();

  constructor({
    host = LISTEN_HOST_DEFAULT,
    port = LISTEN_PORT_DEFAULT,
    cert = FS.readFileSync(Path.join(CERTS_DIR, 'plug2proxy.crt')),
    key = FS.readFileSync(Path.join(CERTS_DIR, 'plug2proxy.key')),
    password,
  }: ServerOptions) {
    this.password = password;

    let lastSessionId = 0;

    let http2SecureServer = HTTP2.createSecureServer({
      settings: {
        initialWindowSize: WINDOW_SIZE,
      },
      maxOutstandingPings: SESSION_MAX_OUTSTANDING_PINGS,
      cert,
      key,
    })
      .on('session', session => {
        // This `session` is HTTP2 session, not Plug2Proxy session.

        session.setLocalWindowSize(WINDOW_SIZE);

        let remoteAddress = session.socket.remoteAddress ?? '(unknown)';

        let ping = (): void => {
          if (session.destroyed) {
            clearInterval(pingTimer);
            return;
          }

          session.ping((error, duration) => {
            if (error) {
              console.error(
                `[server] ping error (remote ${remoteAddress}):`,
                error.message,
              );

              session.destroy();

              return;
            }

            let candidate = this.sessionToSessionCandidateMap.get(session);

            if (!candidate) {
              return;
            }

            let logPrefix = `[${candidate.id}](${remoteAddress})`;

            if (candidate.active) {
              if (duration > candidate.deactivationLatency) {
                candidate.active = false;
                console.info(
                  `${logPrefix} 🟡 session deactivated (latency: ${duration.toFixed(
                    2,
                  )}ms).`,
                );
              }
            } else {
              if (duration < candidate.activationLatency) {
                candidate.active = true;
                console.info(
                  `${logPrefix} 🟢 session activated (latency: ${duration.toFixed(
                    2,
                  )}ms).`,
                );
              }
            }
          });
        };

        let pingTimer = setInterval(ping, SESSION_PING_INTERVAL);

        session
          .on('close', () => {
            clearInterval(pingTimer);
          })
          .on('error', () => {
            clearInterval(pingTimer);
          });

        ping();
      })
      .on('stream', (stream, headers) => {
        if (headers.type !== 'session') {
          let id = headers.id;

          if (typeof id !== 'string') {
            console.error(
              `[server] received unexpected non-session request without id: ${headers.type}`,
            );
            return;
          }

          let streamListener = this.streamListenerMap.get(id);

          if (!streamListener) {
            console.error(
              `[server] received unexpected non-session request with unknown id: ${headers.type} ${id}`,
            );
            return;
          }

          streamListener(stream, headers);

          return;
        }

        let session = stream.session;

        let remoteAddress = session.socket.remoteAddress ?? '(unknown)';

        if (headers.password !== password) {
          console.warn(
            `[server] authentication failed (remote ${remoteAddress}): wrong password`,
          );

          stream.respond(
            {
              ':status': 403,
              message: 'wrong password',
            },
            {
              endStream: true,
            },
          );
          return;
        }

        let id = (++lastSessionId).toString();

        let logPrefix = `[${id}](${remoteAddress})`;

        console.info(`${logPrefix} new session accepted.`);

        let activationLatency =
          Number(headers['activation-latency']) || Infinity;
        let deactivationLatency =
          Number(headers['deactivation-latency']) || Infinity;

        let candidate: SessionCandidate = {
          id,
          stream,
          active: false,
          activationLatency,
          deactivationLatency,
          priority: Number(headers.priority) || 0,
        };

        stream.respond({
          ':status': 200,
          id,
        });

        stream
          .on('close', () => {
            this.sessionToSessionCandidateMap.delete(session);

            console.info(`${logPrefix} 🔴 session "close".`);
          })
          .on('error', error => {
            // Observing more session candidates than expected, pull on error
            // for redundancy.
            this.sessionToSessionCandidateMap.delete(session);

            console.error(`${logPrefix} 🔴 session error:`, error.message);
          });

        this.sessionToSessionCandidateMap.set(session, candidate);

        for (let resolver of this.sessionCandidateResolvers) {
          resolver(candidate);
        }

        this.sessionCandidateResolvers.splice(0);
      });

    http2SecureServer.listen(
      {
        host,
        port,
      },
      () => {
        let address = http2SecureServer.address();

        if (typeof address !== 'string') {
          address = `${address?.address}:${address?.port}`;
        }

        console.info(`[server] waiting for sessions on ${address}...`);
      },
    );

    this.http2SecureServer = http2SecureServer;
  }

  onStream(id: string, listener: ServerStreamListener): () => void {
    let streamListenerMap = this.streamListenerMap;

    streamListenerMap.set(id, listener);

    return () => streamListenerMap.delete(id);
  }

  async getSessionCandidate(logPrefix: string): Promise<SessionCandidate> {
    let allCandidates = Array.from(this.sessionToSessionCandidateMap.values());

    let activeCandidates = allCandidates.filter(candidate => candidate.active);

    let priorityCandidates =
      activeCandidates.length > 0 ? activeCandidates : allCandidates;

    if (priorityCandidates.length > 0) {
      let [firstCandidate, ...restCandidates] = _.sortBy(
        priorityCandidates,
        candidate => -candidate.priority,
      );

      let restPrioritizedEndAt = restCandidates.findIndex(
        candidate => candidate.priority < firstCandidate.priority,
      );

      let prioritizedCandidates = [
        firstCandidate,
        ...(restPrioritizedEndAt < 0
          ? restCandidates
          : restCandidates.slice(0, restPrioritizedEndAt)),
      ];

      console.info(
        `${logPrefix} getting session candidates, ${
          prioritizedCandidates.length
        } (priority ${prioritizedCandidates[0]?.priority ?? 'n/a'}) / ${
          activeCandidates.length
        } / ${allCandidates.length} available.`,
      );

      return _.sample(prioritizedCandidates)!;
    } else {
      console.info(
        `${logPrefix} no session candidate is currently available, waiting for new session...`,
      );

      return new Promise(resolve => {
        this.sessionCandidateResolvers.push(resolve);
      });
    }
  }
}

export interface SessionCandidate {
  id: string;
  priority: number;
  active: boolean;
  activationLatency: number;
  deactivationLatency: number;
  stream: HTTP2.ServerHttp2Stream;
}

export type ServerStreamListener = (
  stream: HTTP2.ServerHttp2Stream,
  headers: HTTP2.IncomingHttpHeaders,
) => void;
