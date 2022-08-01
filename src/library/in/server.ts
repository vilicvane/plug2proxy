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
  private sessionCandidates: SessionCandidate[] = [];
  private sessionCandidateResolvers: ((candidate: SessionCandidate) => void)[] =
    [];

  readonly password: string | undefined;

  readonly http2SecureServer: HTTP2.Http2SecureServer;

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

        let pingTimer = setInterval(() => {
          if (session.destroyed) {
            clearInterval(pingTimer);
            return;
          }

          session.ping(error => {
            if (!error) {
              return;
            }

            console.error(
              `[server] ping error (remote ${remoteAddress}):`,
              error.message,
            );

            session.destroy();
          });
        }, SESSION_PING_INTERVAL);

        session
          .on('close', () => {
            clearInterval(pingTimer);
          })
          .on('error', () => {
            clearInterval(pingTimer);
          });
      })
      .on('stream', (stream, headers) => {
        if (headers.type !== 'session') {
          if (http2SecureServer.listenerCount('stream') === 1) {
            console.error(
              `[server] received unexpected non-session request: ${headers.type}`,
            );
          }

          return;
        }

        let remoteAddress = stream.session.socket.remoteAddress ?? '(unknown)';

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

        let candidate: SessionCandidate = {
          id,
          stream,
        };

        stream.respond({
          ':status': 200,
          id,
        });

        stream
          .on('close', () => {
            _.pull(this.sessionCandidates, candidate);
            console.info(`${logPrefix} session "close".`);
          })
          .on('error', error => {
            // Observing more session candidates than expected, pull on error
            // for redundancy.
            _.pull(this.sessionCandidates, candidate);
            console.error(`${logPrefix} session error:`, error.message);
          });

        this.sessionCandidates.push(candidate);

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

  async getSessionCandidate(logPrefix: string): Promise<SessionCandidate> {
    let candidates = this.sessionCandidates;

    console.debug(
      `${logPrefix} getting session candidates, ${candidates.length} available.`,
    );

    if (candidates.length > 0) {
      return _.sample(candidates)!;
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
  stream: HTTP2.ServerHttp2Stream;
}
