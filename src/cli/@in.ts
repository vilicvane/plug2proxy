import {readFile} from 'fs/promises';

import {In} from '../library/index.js';

import {CA_CERT_PATH, CA_KEY_PATH} from './@constants.js';

export async function setupIn({
  tunnel: tunnelServerOptions,
  proxy: httpProxyOptions,
  ca = In.CONFIG_CA_DEFAULT,
}: In.Config): Promise<void> {
  let caOptions: In.TLSProxyBridgeCAOptions | false;

  if (ca) {
    await In.ensureCA(CA_CERT_PATH, CA_KEY_PATH);

    caOptions = {
      cert: await readFile(CA_CERT_PATH, 'utf8'),
      key: await readFile(CA_KEY_PATH, 'utf8'),
    };
  } else {
    caOptions = false;
  }

  const geolite2 = new In.GeoLite2({});

  const router = new In.Router(geolite2);

  const tunnelServer = new In.TunnelServer(router, {
    cert: await readFile('172.19.32.1.pem', 'utf8'),
    key: await readFile('172.19.32.1-key.pem', 'utf8'),
  });

  const tlsProxyBridge = new In.TLSProxyBridge(tunnelServer, router, {
    ca: caOptions,
  });

  const netProxyBridge = new In.NetProxyBridge(tunnelServer, router);

  const web = new In.Web({
    caCertPath: ca ? CA_CERT_PATH : undefined,
  });

  const proxy = new In.HTTPProxy(
    tunnelServer,
    tlsProxyBridge,
    netProxyBridge,
    web,
    In.HTTPProxyOptions.nominalize({
      host: '',
      port: 8888,
    }),
  );
}
