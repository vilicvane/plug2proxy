import assert from 'assert';
import {once} from 'events';
import * as Net from 'net';
import {Duplex, PassThrough} from 'stream';
import * as TLS from 'tls';

import Forge from '@vilic/node-forge';
import type {Nominal} from 'x-value';

import type {InLogContext} from '../../@log/index.js';
import {
  ALPN_PROTOCOL_CHANGED,
  IN_ALPN_KNOWN_PROTOCOL_SELECTION,
  IN_ALPN_PROTOCOL_CANDIDATES,
  IN_ALPN_PROTOCOL_SELECTION,
  IN_CERTIFICATE_TRUSTED_STATUS_CHANGED,
  IN_CONNECT_SOCKET_CLOSED,
  IN_CONNECT_TLS,
  IN_ERROR_CONNECT_SOCKET_ERROR,
  IN_ERROR_LEFT_SECURE_PROXY_SOCKET_ERROR,
  IN_ERROR_PIPING_CONNECT_SOCKET_FROM_TO_TUNNEL,
  IN_ERROR_READING_REQUEST_HEADERS,
  IN_ERROR_RIGHT_SECURE_PROXY_SOCKET_ERROR,
  IN_ERROR_ROUTING_CONNECTION,
  IN_ERROR_SETTING_UP_LEFT_SECURE_PROXY_SOCKET,
  IN_ERROR_SETTING_UP_RIGHT_SECURE_PROXY_SOCKET,
  IN_ERROR_TUNNEL_CONNECTING,
  IN_OPTIMISTIC_CONNECT,
  IN_SWITCHING_RIGHT_SECURE_PROXY_SOCKET,
  Logs,
} from '../../@log/index.js';
import {
  duplexify,
  errorWhile,
  pipelines,
  streamErrorWhileEntry,
} from '../../@utils/index.js';
import {type ReadTLSResult, readHTTPHeaders} from '../@sniffing.js';
import type {RouteCandidate, Router} from '../router/index.js';
import type {TunnelServer} from '../tunnel-server.js';
import duplexer3 from 'duplexer3';
import {readTlsClientHello} from '@vilic/read-tls-client-hello';

export type TLSProxyBridgeCAOptions = {
  cert: string;
  key: string;
};

export type TLSProxyBridgeOptions = {
  ca: TLSProxyBridgeCAOptions | false;
};

export class TLSProxyBridge {
  readonly ca:
    | {
        cert: Forge.pki.Certificate;
        key: Forge.pki.PrivateKey;
      }
    | undefined;

  private certKeyPair = Forge.pki.rsa.generateKeyPair(2048);

  constructor(
    readonly tunnelServer: TunnelServer,
    readonly router: Router,
    {ca}: TLSProxyBridgeOptions,
  ) {
    if (ca) {
      this.ca = {
        cert: Forge.pki.certificateFromPem(ca.cert),
        key: Forge.pki.privateKeyFromPem(ca.key),
      };
    }
  }

  private knownALPNProtocolMap = new Map<ALPNProtocolKey, string | false>();

  async connect(
    context: InLogContext,
    connectSocket: Net.Socket,
    host: string,
    port: number,
    readTLSResult: ReadTLSResult,
  ): Promise<void> {
    Logs.info(context, IN_CONNECT_TLS(host, port));

    if (this.ca) {
      await this.connectWithCA(
        context,
        connectSocket,
        host,
        port,
        readTLSResult,
      );
    } else {
      await this.connectWithoutCA(context, connectSocket, host, port);
    }
  }

  private async connectWithCA(
    context: InLogContext,
    connectSocket: Net.Socket,
    host: string,
    port: number,
    tlsHelloData: ReadTLSResult,
  ): Promise<void> {
    context.decrypted = true;

    const {serverName, alpnProtocols} = tlsHelloData;

    if (alpnProtocols) {
      Logs.debug(context, IN_ALPN_PROTOCOL_CANDIDATES(alpnProtocols));
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
      return this.performOptimisticConnectWithCA(
        context,
        host,
        port,
        connectSocket,
        tlsHelloData,
      );
    } else {
      Logs.debug(context, IN_ALPN_KNOWN_PROTOCOL_SELECTION(knownALPNProtocol));

      return this.performHTTPConnectWithCA(
        context,
        host,
        port,
        connectSocket,
        knownALPNProtocol,
        tlsHelloData,
      );
    }
  }

  private async connectWithoutCA(
    context: InLogContext,
    connectSocket: Net.Socket,
    host: string,
    port: number,
  ): Promise<void> {
    const connectSocketErrorWhile = streamErrorWhileEntry(
      connectSocket,
      error => Logs.error(context, IN_ERROR_CONNECT_SOCKET_ERROR(error)),
    );

    let route: RouteCandidate | undefined;

    try {
      route = await errorWhile(
        this.router.routeHost(host),
        () => Logs.error(context, IN_ERROR_ROUTING_CONNECTION),
        [connectSocketErrorWhile],
      );
    } catch (error) {
      Logs.debug(context, error);
      return;
    }

    let tunnel: Duplex;

    if (route) {
      try {
        tunnel = await errorWhile(
          this.tunnelServer.connect(context, route, host, port),
          error => Logs.error(context, IN_ERROR_TUNNEL_CONNECTING(error)),
          [connectSocketErrorWhile],
        );
      } catch (error) {
        Logs.debug(context, error);
        return;
      }
    } else {
      tunnel = Net.connect(port, host);
    }

    try {
      await pipelines([
        [connectSocket, tunnel],
        [tunnel, connectSocket],
      ]);

      Logs.info(context, IN_CONNECT_SOCKET_CLOSED);
    } catch (error) {
      Logs.error(context, IN_ERROR_PIPING_CONNECT_SOCKET_FROM_TO_TUNNEL(error));
      Logs.debug(context, error);
    }
  }

  private async performOptimisticConnectWithCA(
    context: InLogContext,
    host: string,
    port: number,
    connectSocket: Net.Socket,
    tlsHelloData: ReadTLSResult,
  ): Promise<void> {
    const {serverName, alpnProtocols} = tlsHelloData;

    Logs.debug(context, IN_OPTIMISTIC_CONNECT);

    const connectSocketErrorWhile = streamErrorWhileEntry(
      connectSocket,
      error => Logs.error(context, IN_ERROR_CONNECT_SOCKET_ERROR(error)),
    );

    let optimisticRoute: RouteCandidate | undefined;

    try {
      optimisticRoute = await errorWhile(
        this.router.routeHost(serverName ?? host),
        () => Logs.error(context, IN_ERROR_ROUTING_CONNECTION),
        [connectSocketErrorWhile],
      );
    } catch (error) {
      Logs.debug(context, error);
      return;
    }

    let rightSecureProxySocket: TLS.TLSSocket;

    try {
      rightSecureProxySocket = await errorWhile(
        this.setupRightSecureProxySocket(
          context,
          optimisticRoute,
          host,
          port,
          tlsHelloData,
        ),
        () =>
          Logs.error(context, IN_ERROR_SETTING_UP_RIGHT_SECURE_PROXY_SOCKET),
        [connectSocketErrorWhile],
      );
    } catch (error) {
      Logs.debug(context, error);
      return;
    }

    const rightSecureProxySocketErrorWhile = streamErrorWhileEntry(
      rightSecureProxySocket,
      error =>
        Logs.error(context, IN_ERROR_RIGHT_SECURE_PROXY_SOCKET_ERROR(error)),
    );

    const alpnProtocol = rightSecureProxySocket.alpnProtocol!;

    Logs.debug(context, IN_ALPN_PROTOCOL_SELECTION(alpnProtocol));

    const certificate = this.getP2PCertificate(
      host,
      port,
      serverName,
      rightSecureProxySocket,
    );

    this.updateALPNProtocol(
      host,
      port,
      serverName,
      alpnProtocols,
      alpnProtocol,
    );

    let leftSecureProxySocket: TLS.TLSSocket;
    let referer: string | undefined;

    try {
      [leftSecureProxySocket, referer] = await errorWhile(
        this.setupLeftSecureProxySocket(
          context,
          connectSocket,
          certificate,
          alpnProtocol,
        ),
        () => Logs.error(context, IN_ERROR_SETTING_UP_LEFT_SECURE_PROXY_SOCKET),
        () => connectSocket.destroy(),
        [rightSecureProxySocketErrorWhile],
      );
    } catch (error) {
      Logs.debug(context, error);
      return;
    }

    const leftSecureProxySocketErrorWhile = streamErrorWhileEntry(
      leftSecureProxySocket,
      error =>
        Logs.error(context, IN_ERROR_LEFT_SECURE_PROXY_SOCKET_ERROR(error)),
    );

    if (referer !== undefined) {
      let refererRoute: RouteCandidate | undefined;

      try {
        refererRoute = await errorWhile(
          this.router.routeURL(referer),
          () => Logs.error(context, IN_ERROR_ROUTING_CONNECTION),
          [leftSecureProxySocketErrorWhile, rightSecureProxySocketErrorWhile],
        );
      } catch (error) {
        Logs.debug(context, error);
        return;
      }

      if (refererRoute && refererRoute.remote !== optimisticRoute?.remote) {
        Logs.info(context, IN_SWITCHING_RIGHT_SECURE_PROXY_SOCKET);

        rightSecureProxySocket.destroy();

        try {
          rightSecureProxySocket = await errorWhile(
            this.setupRightSecureProxySocket(
              context,
              refererRoute,
              host,
              port,
              tlsHelloData,
            ),
            () =>
              Logs.error(
                context,
                IN_ERROR_SETTING_UP_RIGHT_SECURE_PROXY_SOCKET,
              ),
            [leftSecureProxySocketErrorWhile],
          );
        } catch (error) {
          Logs.debug(context, error);
          return;
        }

        // Should update rightSecureProxySocketErrorWhile accordingly but it's
        // never used again.
      }
    }

    await this.pipeLeftRightSecureProxySockets(
      context,
      leftSecureProxySocket,
      rightSecureProxySocket,
    );
  }

  private async performHTTPConnectWithCA(
    context: InLogContext,
    host: string,
    port: number,
    connectSocket: Net.Socket,
    alpnProtocol: string | false,
    tlsHelloData: ReadTLSResult,
  ): Promise<void> {
    const {serverName, alpnProtocols} = tlsHelloData;

    const {certificate, trusted} = this.requireP2PCertificateForKnownRemote(
      host,
      port,
      serverName,
    );

    let leftSecureProxySocket: TLS.TLSSocket;
    let referer: string | undefined;

    try {
      [leftSecureProxySocket, referer] = await this.setupLeftSecureProxySocket(
        context,
        connectSocket,
        certificate,
        alpnProtocol,
      );
    } catch (error) {
      Logs.error(context, IN_ERROR_SETTING_UP_LEFT_SECURE_PROXY_SOCKET);
      Logs.debug(context, error);
      return;
    }

    const leftSecureProxySocketErrorWhile = streamErrorWhileEntry(
      leftSecureProxySocket,
      error =>
        Logs.error(context, IN_ERROR_LEFT_SECURE_PROXY_SOCKET_ERROR(error)),
    );

    let route: RouteCandidate | undefined;

    try {
      route = await errorWhile(
        this.router.route(serverName ?? host, referer),
        () => Logs.error(context, IN_ERROR_ROUTING_CONNECTION),
        [leftSecureProxySocketErrorWhile],
      );
    } catch (error) {
      Logs.debug(context, error);
      return;
    }

    let rightSecureProxySocket: TLS.TLSSocket;

    try {
      rightSecureProxySocket = await errorWhile(
        this.setupRightSecureProxySocket(
          context,
          route,
          host,
          port,
          tlsHelloData,
        ),
        () =>
          Logs.error(context, IN_ERROR_SETTING_UP_RIGHT_SECURE_PROXY_SOCKET),
        [leftSecureProxySocketErrorWhile],
      );
    } catch (error) {
      Logs.debug(context, error);
      return;
    }

    if (isTLSSocketTrusted(rightSecureProxySocket) !== trusted) {
      Logs.info(context, IN_CERTIFICATE_TRUSTED_STATUS_CHANGED);

      this.createP2PCertificate(host, port, serverName, rightSecureProxySocket);

      leftSecureProxySocket.destroy();
      rightSecureProxySocket.destroy();

      return;
    }

    if (rightSecureProxySocket.alpnProtocol !== alpnProtocol) {
      Logs.info(context, ALPN_PROTOCOL_CHANGED);

      this.updateALPNProtocol(
        host,
        port,
        serverName,
        alpnProtocols,
        rightSecureProxySocket.alpnProtocol!,
      );

      leftSecureProxySocket.destroy();
      rightSecureProxySocket.destroy();

      return;
    }

    await this.pipeLeftRightSecureProxySockets(
      context,
      leftSecureProxySocket,
      rightSecureProxySocket,
    );
  }

  private async setupRightSecureProxySocket(
    context: InLogContext,
    route: RouteCandidate | undefined,
    host: string,
    port: number,
    tlsHelloData: ReadTLSResult,
  ): Promise<TLS.TLSSocket> {
    const {serverName, alpnProtocols, raw} = tlsHelloData;

    let rightSecureProxySocket: TLS.TLSSocket;

    let netStream: Duplex;

    if (route) {
      try {
        netStream = await this.tunnelServer.connect(context, route, host, port);
      } catch (error) {
        Logs.error(context, IN_ERROR_TUNNEL_CONNECTING(error));
        throw error;
      }
    } else {
      netStream = Net.connect(port, host);
    }

    const netWritable = new PassThrough();
    const netReadable = new PassThrough();

    const clientHelloPromise = readTlsClientHello(netWritable, {
      consume: true,
    });

    const netDuplex = duplexify(netWritable, netReadable);

    rightSecureProxySocket = TLS.connect({
      socket: netDuplex,
      servername: serverName,
      ALPNProtocols: alpnProtocols,
      rejectUnauthorized: false,
    });

    rightSecureProxySocket.on('keylog', console.log);

    const {raw: nodeRaw} = await clientHelloPromise;

    // bytes
    // 5 record prefix
    // 1 hello type
    // 3 hello length
    // 2 version
    // 32 client random

    const clientRandomStart = 5 + 1 + 3 + 2;

    const nodeClientRandom = nodeRaw.subarray(
      clientRandomStart,
      clientRandomStart + 32,
    );

    // 1 session id length

    const sessionStart = clientRandomStart + 32;
    const sessionLength = raw.readUInt8(sessionStart);

    const nodeSessionLength = nodeRaw.readUInt8(sessionStart);
    const nodeSessionId = nodeRaw.subarray(
      sessionStart,
      sessionStart + 1 + nodeSessionLength,
    );

    const helloChunks: Buffer[] = [
      raw.subarray(0, clientRandomStart),
      nodeClientRandom,
      nodeSessionId,
      raw.subarray(sessionStart + 1 + sessionLength),
    ];

    const hello = Buffer.concat(helloChunks);

    hello.writeUint16BE(hello.length - 5, 3); // record length
    hello.writeIntBE(hello.length - 5 - 4, 5 + 1, 3); // hello length

    const p = new PassThrough();

    setTimeout(() => {
      p.write(hello);
    }, 0);

    const x = await readTlsClientHello(p);

    console.log(x);

    netStream.write(hello);

    // netReadable.on('data', console.log);

    pipelines([
      [netWritable, netStream],
      [netStream, netReadable],
    ]).catch(error => rightSecureProxySocket.emit('error', error));

    await once(rightSecureProxySocket, 'secureConnect');

    return rightSecureProxySocket;
  }

  private async setupLeftSecureProxySocket(
    context: InLogContext,
    connectSocket: Net.Socket,
    {cert, key}: P2PCertificate,
    alpnProtocol: string | false,
  ): Promise<[inTLSSocket: TLS.TLSSocket, referer: string | undefined]> {
    const leftSecureProxySocket = new TLS.TLSSocket(connectSocket, {
      isServer: true,
      ALPNProtocols:
        typeof alpnProtocol === 'string' ? [alpnProtocol] : undefined,
      cert,
      key,
    });

    let headerMap: Map<string, string> | undefined;

    try {
      const result = await readHTTPHeaders(leftSecureProxySocket);

      if (result) {
        headerMap = result.headerMap;
      }
    } catch (error) {
      leftSecureProxySocket.destroy();

      Logs.error(context, IN_ERROR_READING_REQUEST_HEADERS);

      throw error;
    }

    return [leftSecureProxySocket, headerMap?.get('referer')];
  }

  private async pipeLeftRightSecureProxySockets(
    context: InLogContext,
    leftSecureProxySocket: TLS.TLSSocket,
    rightSecureProxySocket: TLS.TLSSocket,
  ): Promise<void> {
    try {
      await pipelines([
        [leftSecureProxySocket, rightSecureProxySocket],
        [rightSecureProxySocket, leftSecureProxySocket],
      ]);

      Logs.info(context, IN_CONNECT_SOCKET_CLOSED);
    } catch (error) {
      Logs.error(context, IN_ERROR_PIPING_CONNECT_SOCKET_FROM_TO_TUNNEL(error));
      Logs.debug(context, error);
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

    const {ca} = this;

    assert(ca);

    const asn1Cert = Forge.asn1.fromDer(
      Forge.util.createBuffer(certificate.raw),
    );

    const {publicKey, privateKey} = this.certKeyPair;

    const cert = Forge.pki.certificateFromAsn1(asn1Cert);

    cert.publicKey = publicKey;

    if (trusted) {
      cert.setIssuer(ca.cert.subject.attributes);
      cert.sign(ca.key, Forge.md.sha512.create());
    } else {
      cert.setIssuer([
        {
          shortName: 'CN',
          value: `Plug2Proxy Untrusted CA (${cert.issuer.getField('CN')})`,
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
