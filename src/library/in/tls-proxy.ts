import assert from 'assert';
import {once} from 'events';
import * as Net from 'net';
import type {Duplex} from 'stream';
import {PassThrough} from 'stream';
import {pipeline} from 'stream/promises';
import * as TLS from 'tls';

import Forge from '@vilic/node-forge';
import Chalk from 'chalk';
import {readTlsClientHello} from 'read-tls-client-hello';
import type {Nominal} from 'x-value';

import type {InConnectLogContext, LogContext} from '../@log.js';
import {Logs} from '../@log.js';
import {
  handleErrorWhile,
  readHTTPRequestStreamHeaders,
} from '../@utils/index.js';
import type {ConnectionId, TunnelId} from '../common.js';

import type {Router} from './router/index.js';
import type {TunnelServer} from './tunnel-server.js';

export type TLSProxyOptions = {
  ca: {
    cert: string;
    key: string;
  };
};

export class TLSProxy {
  readonly caCert: Forge.pki.Certificate;
  readonly caKey: Forge.pki.PrivateKey;

  constructor(
    readonly tunnelServer: TunnelServer,
    readonly router: Router,
    {ca}: TLSProxyOptions,
  ) {
    this.caCert = Forge.pki.certificateFromPem(ca.cert);
    this.caKey = Forge.pki.privateKeyFromPem(ca.key);
  }

  private knownALPNProtocolMap = new Map<ALPNProtocolKey, string | false>();

  async connect(
    id: ConnectionId,
    inSocket: Net.Socket,
    host: string,
    port: number,
  ): Promise<void> {
    const context: InConnectLogContext = {
      type: 'in:connect',
      id,
      host,
      port,
    };

    Logs.info(context, `${Chalk.cyan('connect')} ${host}:${port}...`);

    let alpnProtocols: string[] | undefined;
    let serverName: string | undefined;

    // read client hello for ALPN
    {
      const through = new PassThrough();

      const helloChunks: Buffer[] = [];

      const onHelloData = (data: Buffer): void => {
        helloChunks.push(data);
        through.write(data);
      };

      inSocket.on('data', onHelloData);

      try {
        ({alpnProtocols, serverName} = await handleErrorWhile(
          readTlsClientHello(through),
          [inSocket],
        ));

        if (alpnProtocols) {
          Logs.debug(context, 'alpn protocols (IN):', alpnProtocols.join(', '));
        }
      } catch (error) {
        Logs.warn(context, 'failed to read client hello.');
        Logs.debug(context, error);

        inSocket.destroy();

        return;
      }

      inSocket.off('data', onHelloData);

      inSocket.pause();

      inSocket.unshift(Buffer.concat(helloChunks));
    }

    // If we already know that a specific host with specific ALPN protocols
    // selects a specific protocol, we can wait locally for the request referer
    // to determine the route.

    // Note the alpn protocol is not useful for P2P, and P2P determines the
    // protocol based on request/response.

    // Otherwise, we will do an optimistic connection, assuming route based on
    // the target host (no referer), and retry if the route turns out to be
    // incorrect.

    const knownALPNProtocol = this.knownALPNProtocolMap.get(
      ALPN_PROTOCOL_KEY(host, port, serverName, alpnProtocols),
    );

    if (knownALPNProtocol === undefined) {
      await this.performOptimisticConnect(
        context,
        host,
        port,
        inSocket,
        alpnProtocols,
        serverName,
      );
    } else {
      Logs.debug(context, 'known alpn protocol:', knownALPNProtocol);

      await this.performHTTPConnect(
        context,
        host,
        port,
        inSocket,
        alpnProtocols,
        knownALPNProtocol,
        serverName,
      );
    }
  }

  private async performOptimisticConnect(
    context: InConnectLogContext,
    host: string,
    port: number,
    inSocket: Net.Socket,
    alpnProtocols: string[] | undefined,
    serverName: string | undefined,
  ): Promise<void> {
    Logs.debug(context, 'performing optimistic connect...');

    const optimisticRoute = await this.router.route(host);

    let outTLSSocket: TLS.TLSSocket;

    try {
      outTLSSocket = await this.secureConnectOut(
        context,
        host,
        port,
        optimisticRoute,
        alpnProtocols,
        serverName,
      );
    } catch (error) {
      Logs.error(context, 'failed to establish secure OUT connection.');
      Logs.debug(context, error);

      inSocket.destroy();

      return;
    }

    const alpnProtocol = outTLSSocket.alpnProtocol!;

    Logs.debug(context, 'alpn protocol (OUT):', alpnProtocol || 'none');

    const certificate = this.getP2PCertificate(
      host,
      port,
      serverName,
      outTLSSocket,
    );

    this.updateALPNProtocol(
      host,
      port,
      serverName,
      alpnProtocols,
      alpnProtocol,
    );

    let inTLSSocket: TLS.TLSSocket;
    let referer: string | undefined;

    try {
      [inTLSSocket, referer] = await this.secureConnectIn(
        context,
        inSocket,
        certificate,
        alpnProtocol,
      );
    } catch (error) {
      Logs.debug(context, error);

      return;
    }

    if (referer !== undefined) {
      const refererRoute = await this.router.routeReferer(referer);

      if (refererRoute && optimisticRoute !== refererRoute) {
        Logs.info(
          context,
          'referer route is different from host route, switching OUT connection...',
        );

        try {
          outTLSSocket = await this.secureConnectOut(
            context,
            host,
            port,
            refererRoute,
            alpnProtocols,
            serverName,
          );
        } catch (error) {
          Logs.error(context, 'failed to establish secure OUT connection.');
          Logs.debug(context, error);

          inTLSSocket.destroy();

          return;
        }
      }
    }

    await this.connectInOut(context, inTLSSocket, outTLSSocket);
  }

  private async performHTTPConnect(
    context: InConnectLogContext,
    host: string,
    port: number,
    inSocket: Net.Socket,
    alpnProtocols: string[] | undefined,
    alpnProtocol: string | false,
    serverName: string | undefined,
  ): Promise<void> {
    const {certificate, trusted} = this.requireP2PCertificateForKnownRemote(
      context,
      host,
      port,
      serverName,
    );

    let inTLSSocket: TLS.TLSSocket;
    let referer: string | undefined;

    try {
      [inTLSSocket, referer] = await this.secureConnectIn(
        context,
        inSocket,
        certificate,
        alpnProtocol,
      );
    } catch (error) {
      Logs.debug(context, error);

      return;
    }

    const route =
      referer !== undefined
        ? await this.router.routeReferer(referer)
        : await this.router.route(host);

    let outTLSSocket: TLS.TLSSocket;

    try {
      outTLSSocket = await this.secureConnectOut(
        context,
        host,
        port,
        route,
        alpnProtocols,
        serverName,
      );
    } catch (error) {
      Logs.error(context, 'failed to establish secure OUT connection.');
      Logs.debug(context, error);

      inTLSSocket.destroy();

      return;
    }

    if (isTLSSocketTrusted(outTLSSocket) !== trusted) {
      Logs.info(
        context,
        'certificate trusted status changed, reset connection.',
      );

      this.createP2PCertificate(host, port, serverName, outTLSSocket);

      inTLSSocket.destroy();
      outTLSSocket.destroy();

      return;
    }

    if (outTLSSocket.alpnProtocol !== alpnProtocol) {
      Logs.info(context, 'alpn protocol changed, reset connection.');

      this.updateALPNProtocol(
        host,
        port,
        serverName,
        alpnProtocols,
        outTLSSocket.alpnProtocol!,
      );

      inTLSSocket.destroy();
      outTLSSocket.destroy();

      return;
    }

    await this.connectInOut(context, inTLSSocket, outTLSSocket);
  }

  private async secureConnectOut(
    context: InConnectLogContext,
    host: string,
    port: number,
    tunnelId: TunnelId | undefined,
    alpnProtocols: string[] | undefined,
    serverName: string | undefined,
  ): Promise<TLS.TLSSocket> {
    let stream: Duplex;

    if (tunnelId !== undefined) {
      stream = await this.tunnelServer.connect(
        context.id,
        tunnelId,
        host,
        port,
      );
    } else {
      stream = Net.connect(port, host);
      await once(stream, 'connect');
    }

    const tlsSocket = TLS.connect({
      socket: stream,
      servername: serverName,
      ALPNProtocols: alpnProtocols,
      rejectUnauthorized: false,
    });

    await once(tlsSocket, 'secureConnect');

    Logs.debug(context, 'established secure OUT connection.');

    return tlsSocket;
  }

  private async secureConnectIn(
    context: LogContext,
    socket: Net.Socket,
    {cert, key}: P2PCertificate,
    alpnProtocol: string | false,
  ): Promise<[inTLSSocket: TLS.TLSSocket, referer: string | undefined]> {
    const tlsSocket = new TLS.TLSSocket(socket, {
      isServer: true,
      ALPNProtocols:
        typeof alpnProtocol === 'string' ? [alpnProtocol] : undefined,
      cert,
      key,
    });

    Logs.debug(context, 'established secure IN connection.');

    let headerMap: Map<string, string>;

    try {
      headerMap = await readHTTPRequestStreamHeaders(tlsSocket);
    } catch (error) {
      Logs.error(context, 'failed to read request headers.');

      tlsSocket.destroy();

      throw error;
    }

    return [tlsSocket, headerMap.get('referer')];
  }

  private async connectInOut(
    context: LogContext,
    inTLSSocket: TLS.TLSSocket,
    outTLSSocket: TLS.TLSSocket,
  ): Promise<void> {
    try {
      await Promise.all([
        pipeline(inTLSSocket, outTLSSocket),
        pipeline(outTLSSocket, inTLSSocket),
      ]);

      Logs.info(context, 'connection closed.');
    } catch (error) {
      Logs.error(context, 'connecting IN and OUT resulted in an error.');
      Logs.debug(context, error);

      inTLSSocket.destroy();
      outTLSSocket.destroy();
    }
  }

  private p2pCertificateStateMap = new Map<
    P2PCertificateKey,
    P2PCertificateState
  >();

  private getP2PCertificate(
    host: string,
    port: number,
    serverName: string | undefined,
    tlsSocket: TLS.TLSSocket,
  ): P2PCertificate {
    const {p2pCertificateStateMap} = this;

    const p2pCertificateState = p2pCertificateStateMap.get(
      P2P_CERTIFICATE_KEY(host, port, serverName),
    );

    if (p2pCertificateState) {
      return p2pCertificateState.certificate;
    }

    return this.createP2PCertificate(host, port, serverName, tlsSocket);
  }

  private createP2PCertificate(
    host: string,
    port: number,
    serverName: string | undefined,
    tlsSocket: TLS.TLSSocket,
  ): P2PCertificate {
    const certificate = tlsSocket.getPeerCertificate();
    const trusted = isTLSSocketTrusted(tlsSocket);

    const {caCert, caKey} = this;

    const asn1Cert = Forge.asn1.fromDer(
      Forge.util.createBuffer(certificate.raw),
    );

    const {publicKey, privateKey} = Forge.pki.rsa.generateKeyPair(2048);

    const cert = Forge.pki.certificateFromAsn1(asn1Cert);

    cert.publicKey = publicKey;

    if (trusted) {
      cert.setIssuer(caCert.subject.attributes);
      cert.sign(caKey, Forge.md.sha512.create());
    } else {
      cert.setIssuer([
        {
          shortName: 'CN',
          value: `Plug2Proxy Untrusted (${cert.issuer.getField('CN')})`,
        },
      ]);
      cert.sign(privateKey, Forge.md.sha512.create());
    }

    const {p2pCertificateStateMap} = this;

    const p2pCert = {
      cert: Forge.pki.certificateToPem(cert),
      key: Forge.pki.privateKeyToPem(privateKey),
    };

    p2pCertificateStateMap.set(P2P_CERTIFICATE_KEY(host, port, serverName), {
      certificate: p2pCert,
      trusted,
    });

    return p2pCert;
  }

  private requireP2PCertificateForKnownRemote(
    context: LogContext,
    host: string,
    port: number,
    serverName: string | undefined,
  ): P2PCertificateState {
    const state = this.p2pCertificateStateMap.get(
      P2P_CERTIFICATE_KEY(host, port, serverName),
    );

    assert(state);

    return state;
  }

  private updateALPNProtocol(
    host: string,
    port: number,
    serverName: string | undefined,
    alpnProtocols: string[] | undefined,
    alpnProtocol: string | false,
  ): void {
    const alpnProtocolKey = ALPN_PROTOCOL_KEY(
      host,
      port,
      serverName,
      alpnProtocols,
    );

    const {knownALPNProtocolMap} = this;

    switch (alpnProtocol) {
      case 'http/1.1':
      case 'h2':
        knownALPNProtocolMap.set(alpnProtocolKey, alpnProtocol);
        break;
      default:
        knownALPNProtocolMap.set(alpnProtocolKey, false);
        break;
    }
  }
}

type P2PCertificate = {
  cert: string;
  key: string;
};

type P2PCertificateState = {
  certificate: P2PCertificate;
  trusted: boolean;
};

type P2PCertificateKey = Nominal<'p2p certificate key', string>;

function P2P_CERTIFICATE_KEY(
  host: string,
  port: number,
  serverName: string | undefined,
): P2PCertificateKey {
  let key = `${host}:${port}`;

  if (serverName !== undefined) {
    key += ` ${serverName}`;
  }

  return key as P2PCertificateKey;
}

type ALPNProtocolKey = Nominal<'alpn protocol key', string>;

function ALPN_PROTOCOL_KEY(
  host: string,
  port: number,
  serverName: string | undefined,
  alpnProtocols: string[] | undefined,
): ALPNProtocolKey {
  const hostname = `${host}:${port}`;

  let key = hostname;

  if (serverName !== undefined) {
    key += ` ${serverName}`;
  }

  if (alpnProtocols) {
    key += ` ${alpnProtocols.join(',')}`;
  }

  return key as ALPNProtocolKey;
}

function isTLSSocketTrusted({
  authorized,
  authorizationError,
}: TLS.TLSSocket): boolean {
  if (authorized) {
    return true;
  }

  switch (authorizationError as unknown as string | null) {
    // Those error are supposed to be handled by the real clients (e.g.,
    // browsers).
    case 'CERT_NOT_YET_VALID':
    case 'CERT_HAS_EXPIRED':
    case 'ERR_TLS_CERT_ALTNAME_INVALID':
      return true;
    default:
      return false;
  }
}
