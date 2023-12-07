import {In} from '../library/index.js';

import {CA_CERT_PATH, CA_KEY_PATH} from './@constants.js';

export async function setupIn({
  alias,
  tunnel: tunnelServerConfig = {},
  proxy: httpProxyOptions = {},
  ddns: ddnsOptions,
}: In.Config): Promise<void> {
  let caOptions: In.TLSProxyBridgeCAOptions | false;

  if (
    httpProxyOptions.refererSniffing ??
    In.HTTP_PROXY_REFERER_SNIFFING_OPTIONS_DEFAULT
  ) {
    caOptions = await In.ensureCACertificate(CA_CERT_PATH, CA_KEY_PATH);
  } else {
    caOptions = false;
  }

  const geolite2 = new In.GeoLite2({});

  const router = new In.Router(geolite2);

  const tunnelServer = new In.TunnelServer(router, {
    alias,
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
    caCertPath: caOptions ? CA_CERT_PATH : undefined,
  });

  new In.HTTPProxy(
    tunnelServer,
    tlsProxyBridge,
    netProxyBridge,
    web,
    httpProxyOptions,
  );

  if (ddnsOptions) {
    new In.DDNS(ddnsOptions);
  }
}
