import {once} from 'events';
import {readFile, writeFile} from 'fs/promises';
import {connect} from 'tls';

import Forge from '@vilic/node-forge';

const tlsSocket = connect(443, 'baidu.com');

tlsSocket.on('keylog', data => console.log(data.toString()));

await once(tlsSocket, 'secureConnect');

const asn1 = Forge.asn1.fromDer(
  Forge.util.createBuffer(tlsSocket.getPeerCertificate().raw),
);

const cert = Forge.pki.certificateFromAsn1(asn1);

const caCert = Forge.pki.certificateFromPem(
  await readFile('plug2proxy-ca.crt', 'utf8'),
);
const caKey = Forge.pki.privateKeyFromPem(
  await readFile('plug2proxy-ca.key', 'utf8'),
);

cert.setIssuer(caCert.subject.attributes);
cert.sign(caKey, Forge.md.sha512.create());

const pemCert = Forge.pki.certificateToPem(cert);

await writeFile('baidu.com-self-signed.crt', pemCert);
