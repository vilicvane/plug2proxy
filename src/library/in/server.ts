import * as FS from 'fs';
import * as HTTP2 from 'http2';
import * as Path from 'path';

import bytes from 'bytes';
import _ from 'lodash';
import ms from 'ms';
import * as x from 'x-value';
import * as xn from 'x-value/node';

import {BatchScheduler} from '../@utils';
import {IPPattern, Port} from '../@x-types';

const PRINT_SESSION_CANDIDATES_TIME_SPAN = ms('2s');
const PRINT_SESSION_CANDIDATES_IDLE_TIME_SPAN = ms('30s');

const SESSION_PING_INTERVAL = ms('5s');
const SESSION_MAX_OUTSTANDING_PINGS = 2;

const SESSION_QUALITY_MEASUREMENT_MIN_STATUSES_MULTIPLIER = 0.5;

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

  readonly password: string | undefined;

  readonly http2SecureServer: HTTP2.Http2SecureServer;

  private streamListenerMap = new Map<string, ServerStreamListener>();

  private printSessionCandidatesSchedulerIdleTimer: NodeJS.Timer | undefined;

  private printSessionCandidatesScheduler = new BatchScheduler(() => {
    if (this.printSessionCandidatesSchedulerIdleTimer) {
      clearTimeout(this.printSessionCandidatesSchedulerIdleTimer);
    }

    let sessionCandidates = _.sortBy(
      Array.from(this.sessionToSessionCandidateMap.values()),
      candidate => -candidate.priority,
    );

    console.debug();
    console.debug('[server] session candidates: latency / quality / priority');

    for (let {
      id,
      outLabel,
      active,
      priority,
      latency,
      quality,
    } of sessionCandidates) {
      console.debug(
        `  [${id}](${outLabel}) ${active ? '🟢' : '🟡'} ${
          latency ? `${latency.toFixed(2)}ms` : '-'
        } / ${quality.toFixed(2)} / ${priority}`,
      );
    }

    console.debug();

    this.printSessionCandidatesSchedulerIdleTimer = setTimeout(
      () => this.printSessionCandidatesScheduler.schedule(),
      PRINT_SESSION_CANDIDATES_IDLE_TIME_SPAN,
    );
  }, PRINT_SESSION_CANDIDATES_TIME_SPAN);

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

            candidate.latency = duration;

            if (!isFinite(candidate.activationLatency)) {
              return;
            }

            let logPrefix = `[${candidate.id}](${candidate.outLabel})`;

            let previouslyActive = candidate.active;

            if (candidate.active) {
              if (duration > candidate.deactivationLatency) {
                candidate.active = false;
              }
            } else {
              if (duration < candidate.activationLatency) {
                candidate.active = true;
              }
            }

            candidate.statuses.push(candidate.active);

            if (candidate.statuses.length > candidate.statusesLimit) {
              candidate.statuses.shift();
            }

            let quality =
              candidate.statuses.length >=
              candidate.statusesLimit *
                SESSION_QUALITY_MEASUREMENT_MIN_STATUSES_MULTIPLIER
                ? _.mean(candidate.statuses.map(active => (active ? 1 : 0)))
                : -1;

            candidate.quality = quality;

            switch (candidate.activeOverride) {
              case undefined:
                if (quality < candidate.qualityDeactivationOverride) {
                  candidate.activeOverride = false;
                }

                break;
              case false:
                if (quality >= candidate.qualityActivationOverride) {
                  candidate.activeOverride = undefined;
                }

                break;
            }

            candidate.active = candidate.activeOverride ?? candidate.active;

            if (previouslyActive) {
              if (!candidate.active) {
                console.info(
                  `${logPrefix} 🟡 session deactivated (latency: ${duration.toFixed(
                    2,
                  )}ms).`,
                );
              }
            } else {
              if (candidate.active) {
                console.info(
                  `${logPrefix} 🟢 session activated (latency: ${duration.toFixed(
                    2,
                  )}ms).`,
                );
              }
            }

            if (candidate.active !== previouslyActive) {
              void this.printSessionCandidatesScheduler.schedule();
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

        let outLabel = headers['out-label'] as string | undefined;

        outLabel = outLabel
          ? `${decodeURIComponent(outLabel)}${remoteAddress}`
          : remoteAddress;

        let logPrefix = `[${id}](${outLabel})`;

        console.info(`${logPrefix} new session accepted.`);

        let qualityDeactivationOverride = Number(
          headers['quality-deactivation-override'],
        );
        let qualityActivationOverride = Number(
          headers['quality-activation-override'],
        );

        if (isNaN(qualityDeactivationOverride)) {
          qualityDeactivationOverride = 0;
        }

        if (isNaN(qualityActivationOverride)) {
          qualityActivationOverride = 0;
        }

        let sessionQualityMeasurementDuration =
          Number(headers['quality-measurement-duration']) ||
          SESSION_PING_INTERVAL;

        let statusesLimit = Math.ceil(
          sessionQualityMeasurementDuration / SESSION_PING_INTERVAL,
        );

        let activationLatency = Number(headers['activation-latency']);
        let deactivationLatency = Number(headers['deactivation-latency']);

        if (isNaN(activationLatency)) {
          activationLatency = Infinity;
        }

        if (isNaN(deactivationLatency)) {
          deactivationLatency = Infinity;
        }

        let active = isFinite(activationLatency) ? false : true;

        let priority = Number(headers.priority) || 0;

        let candidate: SessionCandidate = {
          id,
          outLabel,
          stream,
          active,
          activeOverride: undefined,
          latency: undefined,
          statuses: [],
          quality: active ? 1 : 0,
          activationLatency,
          deactivationLatency,
          statusesLimit,
          qualityDeactivationOverride,
          qualityActivationOverride,
          priority,
        };

        stream.respond({
          ':status': 200,
          id,
        });

        stream
          .on('close', () => {
            this.sessionToSessionCandidateMap.delete(session);

            void this.printSessionCandidatesScheduler.schedule();

            console.info(`${logPrefix} 🔴 session "close".`);
          })
          .on('error', error => {
            // Observing more session candidates than expected, pull on error
            // for redundancy.
            this.sessionToSessionCandidateMap.delete(session);

            void this.printSessionCandidatesScheduler.schedule();

            console.error(`${logPrefix} 🔴 session error:`, error.message);
          });

        this.sessionToSessionCandidateMap.set(session, candidate);

        void this.printSessionCandidatesScheduler.schedule();

        for (let resolver of this.sessionCandidateResolvers) {
          resolver(candidate);
        }

        this.sessionCandidateResolvers.splice(0);

        if (active) {
          console.info(`${logPrefix} 🟢 session activated.`);
        }
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

      let candidate = _.sample(prioritizedCandidates)!;

      console.info(
        `${logPrefix} get session candidate (${candidate.outLabel}) out of ${
          prioritizedCandidates.length
        } (priority ${candidate.priority ?? 'n/a'}), ${
          activeCandidates.length
        } active / ${allCandidates.length} in total.`,
      );

      return candidate;
    } else {
      console.info(
        `${logPrefix} no session candidate is currently available, waiting for new session...`,
      );

      return new Promise(resolve =>
        this.sessionCandidateResolvers.push(candidate => {
          console.info(
            `${logPrefix} get new session candidate (${candidate.outLabel}).`,
          );

          resolve(candidate);
        }),
      );
    }
  }
}

export interface SessionCandidate {
  id: string;
  outLabel: string;
  priority: number;
  active: boolean;
  activeOverride: false | undefined;
  statuses: boolean[];
  quality: number;
  latency: number | undefined;
  activationLatency: number;
  deactivationLatency: number;
  statusesLimit: number;
  qualityDeactivationOverride: number;
  qualityActivationOverride: number;
  stream: HTTP2.ServerHttp2Stream;
}

export type ServerStreamListener = (
  stream: HTTP2.ServerHttp2Stream,
  headers: HTTP2.IncomingHttpHeaders,
) => void;
