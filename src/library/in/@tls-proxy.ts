import {once} from 'events';
import * as Net from 'net';
import {PassThrough} from 'stream';
import {pipeline} from 'stream/promises';
import * as TLS from 'tls';

import Forge from '@vilic/node-forge';
import {readTlsClientHello} from 'read-tls-client-hello';

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
    inSocket: Net.Socket,
    host: string,
    port: number,
  ): Promise<void> {
    console.log(`connect ${host}:${port}`);

    const through = new PassThrough();

    const helloChunks: Buffer[] = [];

    const onHelloData = (data: Buffer): void => {
      console.log({data});

      helloChunks.push(data);
      through.write(data);
    };

    inSocket.write(`HTTP/1.1 200 OK\r\n\r\n`);

    inSocket.on('data', onHelloData);

    const {alpnProtocols} = await readTlsClientHello(through);

    console.log('in tls alpn protocols', alpnProtocols);

    inSocket.off('data', onHelloData);

    inSocket.unpipe(); // redundant?
    inSocket.pause();

    inSocket.unshift(Buffer.concat(helloChunks));

    const outSocket = await this.connectRemote(host, port);

    console.log('remote connected');

    const outTLSSocket = TLS.connect({
      socket: outSocket,
      ALPNProtocols: alpnProtocols,
    });

    await once(outTLSSocket, 'secureConnect');

    console.log('remote secure connected');

    const remoteCertificate = outTLSSocket.getPeerCertificate();

    const {cert, key} = this.getP2PCertificate(
      remoteCertificate,
      outTLSSocket.authorized,
    );

    const inTLSSocket = new TLS.TLSSocket(inSocket, {
      isServer: true,
      ALPNProtocols: alpnProtocols,
      cert,
      key,
    });

    await Promise.all([
      pipeline(inTLSSocket, outTLSSocket),
      pipeline(outTLSSocket, inTLSSocket),
    ]);
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
