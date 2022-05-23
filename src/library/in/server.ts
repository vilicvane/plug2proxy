import * as FS from 'fs';
import * as HTTP2 from 'http2';
import * as Net from 'net';
import * as Path from 'path';

import _ from 'lodash';

const HTTP2_OPTIONS_DEFAULT: HTTP2.SecureServerOptions = {
  key: FS.readFileSync(Path.join(__dirname, '../../../certs/plug2proxy.key')),
  cert: FS.readFileSync(Path.join(__dirname, '../../../certs/plug2proxy.crt')),
};

export interface ServerOptions {
  /**
   * 明文密码（TLS 中传输）。
   */
  password?: string;
  /**
   * 监听选项，供代理出口连接（注意此端口通常需要在防火墙中允许）。如：
   *
   * ```json
   * {
   *   "port": 8001
   * }
   * ```
   */
  listen: Net.ListenOptions;
  /**
   * HTTP2 选项，配置证书等。如：
   *
   * ```json
   * {
   *   "cert": "-----BEGIN CERTIFICATE-----\n[...]\n-----END CERTIFICATE-----",
   *   "key": "-----BEGIN PRIVATE KEY-----\n[...]\n-----END PRIVATE KEY-----",
   * }
   * ```
   *
   * 如果使用 .js 配置文件，则可以直接使用 FS 模块证书。如：
   *
   * ```js
   * {
   *   cert: FS.readFileSync('localhost-cert.pem'),
   *   key: FS.readFileSync('localhost-key.pem'),
   * };
   * ```
   *
   * 默认值为 Common Name 是 plug2proxy 的过期证书，需配合出口
   * `connect.options.rejectUnauthorized: false` 使用。
   */
  http2?: HTTP2.SecureServerOptions;
}

export class Server {
  private sessionCandidates: SessionCandidate[] = [];
  private sessionCandidateResolvers: ((candidate: SessionCandidate) => void)[] =
    [];

  readonly password: string | undefined;

  readonly http2SecureServer: HTTP2.Http2SecureServer;

  constructor({
    password,
    listen: listenOptions,
    http2: http2Options = HTTP2_OPTIONS_DEFAULT,
  }: ServerOptions) {
    this.password = password;

    let lastSessionId = 0;

    let http2SecureServer = HTTP2.createSecureServer(http2Options);

    http2SecureServer.on('stream', (stream, headers) => {
      if (headers.type !== 'session') {
        if (http2SecureServer.listenerCount('stream') === 1) {
          console.error(
            `received unexpected non-session request: ${headers.type}`,
          );
        }

        return;
      }

      let remoteAddress = stream.session.socket.remoteAddress ?? '(unknown)';

      if (headers.password !== password) {
        console.warn(
          `authentication failed (remote ${remoteAddress}): wrong password`,
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
          console.error(`${logPrefix} session error:`, error.message);
        });

      this.sessionCandidates.push(candidate);

      for (let resolver of this.sessionCandidateResolvers) {
        resolver(candidate);
      }

      this.sessionCandidateResolvers.splice(0);
    });

    http2SecureServer.listen(listenOptions, () => {
      let address = http2SecureServer.address();

      if (typeof address !== 'string') {
        address = `${address?.address}:${address?.port}`;
      }

      console.info(`waiting for sessions on ${address}...`);
    });

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
