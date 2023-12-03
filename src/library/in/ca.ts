import {mkdir, writeFile} from 'fs/promises';
import {dirname} from 'path';

import Forge from '@vilic/node-forge';

import {gentleStat} from '../@utils/index.js';

export async function ensureCA(
  certPath: string,
  keyPath: string,
): Promise<void> {
  const [certStats, keyStats] = await Promise.all([
    gentleStat(certPath),
    gentleStat(keyPath),
  ]);

  if (certStats && keyStats) {
    return;
  }

  if ((certStats && !keyStats) || (!certStats && keyStats)) {
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

  await writeFile(certPath, Forge.pki.certificateToPem(cert));
  await writeFile(keyPath, Forge.pki.privateKeyToPem(privateKey));
}
