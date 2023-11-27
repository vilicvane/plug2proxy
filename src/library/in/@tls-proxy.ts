import {once} from 'events';
import {createWriteStream} from 'fs';
import {Http2Session} from 'http2';
import * as Net from 'net';
import {Duplex, PassThrough} from 'stream';
import {pipeline} from 'stream/promises';
import * as TLS from 'tls';

import Forge from '@vilic/node-forge';
import Duplexify from 'duplexify';
import HPack from 'hpack.js';
import {HTTPParser} from 'http-parser-js';
import {readTlsClientHello} from 'read-tls-client-hello';
import type {Nominal} from 'x-value';

import {type LogContext, Logs} from '../@log.js';

export type TLSProxyOptions = {
  ca: {
    cert: string;
    key: string;
  };
};

export class TLSProxy {
  readonly caCert: Forge.pki.Certificate;
  readonly caKey: Forge.pki.PrivateKey;

  constructor({ca}: TLSProxyOptions) {
    this.caCert = Forge.pki.certificateFromPem(ca.cert);
    this.caKey = Forge.pki.privateKeyFromPem(ca.key);
  }

  private knownALPNProtocolMap = new Map<
    ALPNProtocolKey,
    ALPNProtocol | false
  >();

  protected async connect(
    id: number,
    inSocket: Net.Socket,
    host: string,
    port: number,
  ): Promise<void> {
    const context: LogContext = {
      type: 'connect',
      id,
      hostname: `${host}:${port}`,
    };

    Logs.info(context);

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
        ({alpnProtocols, serverName} = await readTlsClientHello(through));

        if (alpnProtocols) {
          Logs.debug(context, 'alpn protocols (in):', alpnProtocols.join(', '));
        }
      } catch (error) {
        Logs.warn(context, 'failed to read client hello.');
        Logs.debug(context, error);
      }

      inSocket.off('data', onHelloData);

      inSocket.unpipe(); // redundant?
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
      ALPN_PROTOCOL_KEY(host, port, alpnProtocols),
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

      // should not have two different handling here.

      switch (knownALPNProtocol) {
        case 'http/1.1':
        case false:
          await this.performHTTPConnect(
            context,
            host,
            port,
            inSocket,
            alpnProtocols,
            knownALPNProtocol,
            serverName,
          );
          break;
        case 'h2':
          await this.performHTTP2Connect(host, port);
          break;
      }
    }
  }

  private async performOptimisticConnect(
    context: LogContext,
    host: string,
    port: number,
    inSocket: Net.Socket,
    alpnProtocols: string[] | undefined,
    serverName: string | undefined,
  ) {
    Logs.debug(context, 'performing optimistic connect...');

    let outSocket: Net.Socket;

    try {
      outSocket = await this.connectRemote(host, port);
    } catch (error) {
      Logs.error(context, 'failed to connect remote.');
      Logs.debug(context, error);

      inSocket.destroy();

      return;
    }

    Logs.debug(context, 'connected to remote.');

    const outTLSSocket = TLS.connect({
      socket: outSocket,
      servername: serverName,
      ALPNProtocols: alpnProtocols,
    });

    try {
      await once(outTLSSocket, 'secureConnect');
    } catch (error) {
      Logs.error(context, 'failed to create secure connection to remote.');
      Logs.debug(context, error);

      inSocket.destroy();
      outSocket.destroy();

      return;
    }

    const alpnProtocol = outTLSSocket.alpnProtocol!;

    Logs.debug(context, 'secure connection to remote established.');
    Logs.debug(context, 'alpn protocol (out):', alpnProtocol || 'none');

    this.updateALPNProtocol(host, port, alpnProtocols, alpnProtocol);

    const {cert, key} = this.getP2PCertificate(
      host,
      port,
      outTLSSocket.getPeerCertificate(),
      outTLSSocket.authorized,
    );

    const inTLSSocket = new TLS.TLSSocket(inSocket, {
      isServer: true,
      ALPNProtocols: alpnProtocol ? [alpnProtocol] : undefined,
      cert,
      key,
    });

    try {
      await Promise.all([
        pipeline(inTLSSocket, outTLSSocket),
        pipeline(outTLSSocket, inTLSSocket),
      ]);
    } catch (error) {
      Logs.error(context, 'failed to create secure connection to remote.');
      Logs.debug(context, error);

      inSocket.destroy();
      outSocket.destroy();
    }
  }

  private async performHTTPConnect(
    context: LogContext,
    host: string,
    port: number,
    inSocket: Net.Socket,
    alpnProtocols: string[] | undefined,
    alpnProtocol: ALPNProtocol | false,
    serverName: string | undefined,
  ) {
    const {
      id: certificateId,
      certificate: {cert, key},
      authorized,
    } = this.requireP2PCertificateForKnownRemote(host, port);

    const inTLSSocket = new TLS.TLSSocket(inSocket, {
      isServer: true,
      ALPNProtocols: alpnProtocol ? [alpnProtocol] : undefined,
      cert,
      key,
    });

    const headerMap = new Map<string, string>();

    try {
      await new Promise<void>((resolve, reject) => {
        const peekedChunks: Buffer[] = [];

        const parser = new HTTPParser(HTTPParser.REQUEST);

        parser.onHeadersComplete = ({headers}) => {
          for (let index = 0; index < headers.length; index += 2) {
            headerMap.set(headers[index].toLowerCase(), headers[index + 1]);
          }

          inTLSSocket.off('data', onInTLSSocketData);
          inTLSSocket.off('error', reject);

          inTLSSocket.pause();
          inTLSSocket.unshift(Buffer.concat(peekedChunks));

          resolve();
        };

        const onInTLSSocketData = (data: Buffer): void => {
          peekedChunks.push(data);
          parser.execute(data);
        };

        inTLSSocket.on('data', onInTLSSocketData).on('error', reject);
      });
    } catch (error) {
      Logs.error(context, 'failed to read referer.');
      Logs.debug(context, error);
    }

    let outSocket: Net.Socket;

    try {
      outSocket = await this.connectRemote(
        host,
        port,
        headerMap.get('referer'),
      );
    } catch (error) {
      Logs.error(context, 'failed to connect remote.');
      Logs.debug(context, error);

      inSocket.destroy();

      return;
    }

    const outTLSSocket = TLS.connect({
      socket: outSocket,
      servername: serverName,
      ALPNProtocols: alpnProtocols,
    });

    try {
      await once(outTLSSocket, 'secureConnect');
    } catch (error) {
      Logs.error(context, 'failed to create secure connection to remote.');
      Logs.debug(context, error);

      inSocket.destroy();
      outSocket.destroy();

      return;
    }

    if (outTLSSocket.authorized !== authorized) {
      Logs.info(
        context,
        'certificate authorized status changed, reset connection.',
      );

      this.createP2PCertificate(
        host,
        port,
        outTLSSocket.getPeerCertificate(),
        outTLSSocket.authorized,
      );

      inSocket.destroy();
      outSocket.destroy();

      return;
    }

    if (outTLSSocket.alpnProtocol !== alpnProtocol) {
      Logs.info(context, 'alpn protocol changed, reset connection.');

      this.updateALPNProtocol(
        host,
        port,
        alpnProtocols,
        outTLSSocket.alpnProtocol!,
      );

      inSocket.destroy();
      outSocket.destroy();

      return;
    }

    // TODO: upgrade h2c

    try {
      await Promise.all([
        pipeline(inTLSSocket, outTLSSocket),
        pipeline(outTLSSocket, inTLSSocket),
      ]);
    } catch (error) {
      Logs.error(context, 'failed to create secure connection to remote.');
      Logs.debug(context, error);

      inSocket.destroy();
      outSocket.destroy();
    }
  }

  private async performHTTP2Connect(host: string, port: number) {}

  private async connectRemote(
    host: string,
    port: number,
    referer?: string,
  ): Promise<Net.Socket> {
    const socket = Net.connect(port, host);

    await once(socket, 'connect');

    return socket;
  }

  private p2pCertificateMap = new Map<CertificateId, P2PCertificate>();

  private certificateStateMap = new Map<
    CertificateStateKey,
    {
      id: CertificateId;
      authorized: boolean;
    }
  >();

  private getP2PCertificate(
    host: string,
    port: number,
    certificate: TLS.PeerCertificate,
    authorized: boolean,
  ): P2PCertificate {
    const {p2pCertificateMap} = this;

    const id = CERTIFICATE_ID(certificate);

    const p2pCert = p2pCertificateMap.get(id);

    if (p2pCert) {
      return p2pCert;
    }

    return this.createP2PCertificate(host, port, certificate, authorized);
  }

  private createP2PCertificate(
    host: string,
    port: number,
    certificate: TLS.PeerCertificate,
    authorized: boolean,
  ): P2PCertificate {
    const {caCert, caKey} = this;

    const asn1Cert = Forge.asn1.fromDer(
      Forge.util.createBuffer(certificate.raw),
    );

    const {publicKey, privateKey} = Forge.pki.rsa.generateKeyPair(2048);

    const cert = Forge.pki.certificateFromAsn1(asn1Cert);

    cert.publicKey = publicKey;

    if (authorized) {
      cert.setIssuer(caCert.subject.attributes);
      cert.sign(caKey, Forge.md.sha512.create());
    } else {
      cert.setIssuer([
        {
          shortName: 'CN',
          value: `Plug2Proxy Unauthorized CA (${cert.issuer.getField('CN')})`,
        },
      ]);
      cert.sign(privateKey, Forge.md.sha512.create());
    }

    const {p2pCertificateMap, certificateStateMap} = this;

    const id = CERTIFICATE_ID(certificate);

    const p2pCert = {
      cert: Forge.pki.certificateToPem(cert),
      key: Forge.pki.privateKeyToPem(privateKey),
    };

    p2pCertificateMap.set(id, p2pCert);

    certificateStateMap.set(CERTIFICATE_STATE_KEY(host, port), {
      id,
      authorized,
    });

    return p2pCert;
  }

  private requireP2PCertificateForKnownRemote(
    host: string,
    port: number,
  ): {
    id: CertificateId;
    certificate: P2PCertificate;
    authorized: boolean;
  } {
    const state = this.certificateStateMap.get(
      CERTIFICATE_STATE_KEY(host, port),
    );

    if (!state) {
      throw new Error(
        'Not expecting requiring P2P certificate for unknown remote.',
      );
    }

    const {authorized, id} = state;

    const certificate = this.p2pCertificateMap.get(id)!;

    return {
      id,
      certificate,
      authorized,
    };
  }

  private updateALPNProtocol(
    host: string,
    port: number,
    alpnProtocols: string[] | undefined,
    alpnProtocol: string | false,
  ): void {
    const alpnProtocolKey = ALPN_PROTOCOL_KEY(host, port, alpnProtocols);

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

type CertificateStateKey = Nominal<'certificate state key', string>;

function CERTIFICATE_STATE_KEY(host: string, port: number): CertificateStateKey;
function CERTIFICATE_STATE_KEY(host: string, port: number): string {
  return `${host}:${port}`;
}

type CertificateId = Nominal<'certificate id', string>;

function CERTIFICATE_ID(certificate: TLS.PeerCertificate): CertificateId;
function CERTIFICATE_ID({
  issuer: {CN},
  serialNumber,
}: TLS.PeerCertificate): string {
  return `${CN} ${serialNumber}`;
}

type ALPNProtocol = 'h2' | 'http/1.1';

type ALPNProtocolKey = Nominal<'alpn protocol key', string>;

function ALPN_PROTOCOL_KEY(
  host: string,
  port: number,
  alpnProtocols: string[] | undefined,
): ALPNProtocolKey;
function ALPN_PROTOCOL_KEY(
  host: string,
  port: number,
  alpnProtocols: string[] | undefined,
): string {
  const hostname = `${host}:${port}`;

  return alpnProtocols ? `${hostname} ${alpnProtocols.join(',')}` : hostname;
}
