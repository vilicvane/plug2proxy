import * as HTTP2 from 'http2';
import * as Net from 'net';

import _ from 'lodash';

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
   */
  http2: HTTP2.ServerOptions;
}

export class Server {
  private sessionStreams: HTTP2.ServerHttp2Stream[] = [];
  private sessionStreamResolvers: ((
    session: HTTP2.ServerHttp2Stream,
  ) => void)[] = [];

  readonly password: string | undefined;

  readonly http2SecureServer: HTTP2.Http2SecureServer;

  constructor({
    password,
    listen: listenOptions,
    http2: http2Options,
  }: ServerOptions) {
    this.password = password;

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

      console.info(`new session accepted (remote ${remoteAddress}).`);

      stream.respond({
        ':status': 200,
      });

      stream.on('close', () => {
        _.pull(this.sessionStreams, stream);
        console.info(`session closed (remote ${remoteAddress}).`);
      });

      this.sessionStreams.push(stream);

      for (let resolver of this.sessionStreamResolvers) {
        resolver(stream);
      }

      this.sessionStreamResolvers.splice(0);
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

  async getSessionStream(logPrefix: string): Promise<HTTP2.ServerHttp2Stream> {
    let streams = this.sessionStreams;

    console.debug(
      `${logPrefix} getting session stream, ${streams.length} stream(s) available`,
    );

    if (streams.length > 0) {
      return _.sample(streams)!;
    } else {
      console.info(
        `${logPrefix} no session is currently available, waiting for new session...`,
      );

      return new Promise(resolve => {
        this.sessionStreamResolvers.push(resolve);
      });
    }
  }
}
