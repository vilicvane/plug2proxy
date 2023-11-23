import {once} from 'events';
import {createWriteStream} from 'fs';
import {Http2Session} from 'http2';
import * as Net from 'net';
import {PassThrough} from 'stream';
import {pipeline} from 'stream/promises';
import * as TLS from 'tls';

import Forge from '@vilic/node-forge';
import HPack from 'hpack.js';
import {readTlsClientHello} from 'read-tls-client-hello';

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

    let inTLSSocket: TLS.TLSSocket;

    {
      const {alpnProtocol} = outTLSSocket;

      Logs.debug(context, 'secure connection to remote established.');
      Logs.debug(context, 'alpn protocol (out):', alpnProtocol || 'none');

      const remoteCertificate = outTLSSocket.getPeerCertificate();

      const {cert, key} = this.getP2PCertificate(
        remoteCertificate,
        outTLSSocket.authorized,
      );

      inTLSSocket = new TLS.TLSSocket(inSocket, {
        isServer: true,
        ALPNProtocols:
          typeof alpnProtocol === 'string' ? [alpnProtocol] : undefined,
        cert,
        key,
      });
    }

    // Scenarios:

    // 1. HTTPS
    // 2. HTTP/2 via ALPN or prior knowledge
    // 3. HTTP/2 via Upgrade

    const s = createWriteStream('http2-stream.bin');

    inTLSSocket.on('data', data => {
      s.write(data);
    });

    // new (inTLSSocket);

    // {
    //   const through = new PassThrough();

    //   try {
    //     await Promise.all([
    //       pipeline(inTLSSocket, outTLSSocket),
    //       pipeline(outTLSSocket, inTLSSocket),
    //     ]);
    //   } catch (error) {
    //     Logs.error(context, 'failed to create secure connection to remote.');
    //     Logs.debug(context, error);

    //     inSocket.destroy();
    //     outSocket.destroy();
    //   }
    // }
  }

  private p2pCertificateMap = new Map<string, P2PCertificate>();

  private getP2PCertificate(
    {issuer, serialNumber, raw}: TLS.PeerCertificate,
    trusted: boolean,
  ): P2PCertificate {
    const {p2pCertificateMap} = this;

    const id = `${issuer.CN} ${serialNumber}`;

    let cert = p2pCertificateMap.get(id);

    if (!cert) {
      cert = this.createP2PCertificate(raw, trusted);
      p2pCertificateMap.set(id, cert);
    }

    return cert;
  }

  private createP2PCertificate(raw: Buffer, trusted: boolean): P2PCertificate {
    const {caCert, caKey} = this;

    const asn1Cert = Forge.asn1.fromDer(Forge.util.createBuffer(raw));

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
          value: `Plug2Proxy Untrusted CA (${cert.issuer.getField('CN')})`,
        },
      ]);
      cert.sign(privateKey, Forge.md.sha512.create());
    }

    return {
      cert: Forge.pki.certificateToPem(cert),
      key: Forge.pki.privateKeyToPem(privateKey),
    };
  }

  private async connectRemote(host: string, port: number): Promise<Net.Socket> {
    const socket = Net.connect(port, host);

    await once(socket, 'connect');

    return socket;
  }
}

type P2PCertificate = {
  cert: string;
  key: string;
};
