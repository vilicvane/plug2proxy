import {mkdir, readFile, writeFile} from 'fs/promises';
import {dirname} from 'path';

import Forge from '@vilic/node-forge';

export async function ensureCACertificate(
  certPath: string,
  keyPath: string,
): Promise<{cert: string; key: string}> {
  let pemCert = await readFile(certPath, 'utf8').catch(() => undefined);
  let pemKey = await readFile(keyPath, 'utf8').catch(() => undefined);

  if (pemCert !== undefined && pemKey !== undefined) {
    return {
      cert: pemCert,
      key: pemKey,
    };
  }

  if (
    (pemCert !== undefined && pemKey === undefined) ||
    (pemCert === undefined && pemKey !== undefined)
  ) {
    throw new Error(
      'Either both cert and key must exist or neither must exist.',
    );
  }

  const {privateKey, publicKey} = Forge.pki.rsa.generateKeyPair(2048);

  const attributes = [
    {
      shortName: 'CN',
      value: 'Plug2Proxy CA',
    },
  ];

  const extensions = [
    {
      name: 'basicConstraints',
      cA: true,
    },
    {
      name: 'keyUsage',
      keyCertSign: true,
      cRLSign: true,
    },
  ];

  const cert = Forge.pki.createCertificate();

  const validityNotAfter = new Date(cert.validity.notAfter);

  validityNotAfter.setFullYear(validityNotAfter.getFullYear() + 99);

  cert.publicKey = publicKey;
  cert.validity.notAfter = validityNotAfter;
  cert.setSubject(attributes);
  cert.setIssuer(attributes);
  cert.setExtensions(extensions);

  cert.sign(privateKey, Forge.md.sha512.create());

  await mkdir(dirname(certPath), {recursive: true});
  await mkdir(dirname(keyPath), {recursive: true});

  pemCert = Forge.pki.certificateToPem(cert);
  pemKey = Forge.pki.privateKeyToPem(privateKey);

  await writeFile(certPath, pemCert);
  await writeFile(keyPath, pemKey);

  return {
    cert: pemCert,
    key: pemKey,
  };
}

export async function getSelfSignedCertificate(
  commonName: string,
): Promise<{cert: string; key: string}> {
  const {privateKey, publicKey} = Forge.pki.rsa.generateKeyPair(2048);

  const cert = Forge.pki.createCertificate();

  const validityNotAfter = new Date(cert.validity.notAfter);

  validityNotAfter.setFullYear(validityNotAfter.getFullYear() + 99);

  cert.publicKey = publicKey;
  cert.validity.notAfter = validityNotAfter;
  cert.setSubject([
    {
      shortName: 'CN',
      value: commonName,
    },
  ]);
  cert.setIssuer([
    {
      shortName: 'CN',
      value: 'Plug2Proxy Self-Signed',
    },
  ]);

  cert.sign(privateKey, Forge.md.sha512.create());

  const pemCert = Forge.pki.certificateToPem(cert);
  const pemKey = Forge.pki.privateKeyToPem(privateKey);

  return {
    cert: pemCert,
    key: pemKey,
  };
}
