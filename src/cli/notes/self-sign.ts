import {writeFile} from 'fs/promises';

import Forge from '@vilic/node-forge';

const {privateKey, publicKey} = Forge.pki.rsa.generateKeyPair(2048);

const attributes = [
  {
    shortName: 'CN',
    value: 'example.com',
  },
];

const cert = Forge.pki.createCertificate();

const validityNotAfter = new Date(cert.validity.notAfter);

validityNotAfter.setFullYear(validityNotAfter.getFullYear() + 99);

// Set the Certificate attributes for the new Root CA
cert.publicKey = publicKey;
cert.validity.notAfter = validityNotAfter;
cert.setSubject([
  {
    shortName: 'CN',
    value: 'example.com',
  },
]);
cert.setIssuer([
  {
    shortName: 'CN',
    value: 'Plug2Proxy Untrusted CA',
  },
]);

// Self-sign the Certificate
cert.sign(privateKey, Forge.md.sha512.create());

// Convert to PEM format
const pemCert = Forge.pki.certificateToPem(cert);
const pemKey = Forge.pki.privateKeyToPem(privateKey);

console.log({pemCert, pemKey});

await writeFile('plug2proxy-ss.crt', pemCert);
await writeFile('plug2proxy-ss.key', pemKey);
