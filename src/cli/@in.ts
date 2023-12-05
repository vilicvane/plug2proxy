import {In} from '../library/index.js';

import {CA_CERT_PATH, CA_KEY_PATH} from './@constants.js';

export async function setupIn({
  tunnel: tunnelServerConfig = {},
  proxy: httpProxyOptions = {},
}: In.Config): Promise<void> {
  let caOptions: In.TLSProxyBridgeCAOptions | false;

  const {ca = In.CONFIG_PROXY_CA_DEFAULT} = httpProxyOptions;

  if (ca) {
    caOptions = await In.ensureCACertificate(CA_CERT_PATH, CA_KEY_PATH);
  } else {
    caOptions = false;
  }

  const geolite2 = new In.GeoLite2({});

  const router = new In.Router(geolite2);

  const tunnelServer = new In.TunnelServer(router, {
    ...('cert' in tunnelServerConfig && 'key' in tunnelServerConfig
      ? tunnelServerConfig
      : {
          ...tunnelServerConfig,
          ...(await In.getSelfSignedCertificate('tunnel-server.plug2proxy')),
        }),
  });

  const tlsProxyBridge = new In.TLSProxyBridge(tunnelServer, router, {
    ca: caOptions,
  });

  const netProxyBridge = new In.NetProxyBridge(tunnelServer, router);

  const web = new In.Web({
    caCertPath: ca ? CA_CERT_PATH : undefined,
  });

  new In.HTTPProxy(
    tunnelServer,
    tlsProxyBridge,
    netProxyBridge,
    web,
    httpProxyOptions,
  );
}
