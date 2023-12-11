import {ensureCACertificate, getSelfSignedCertificate} from './certificate.js';
import type {Config} from './config.js';
import {DDNS} from './ddns/index.js';
import {
  HTTPProxy,
  HTTP_PROXY_REFERER_SNIFFING_OPTIONS_DEFAULT,
} from './http-proxy.js';
import {
  NetProxyBridge,
  TLSProxyBridge,
  type TLSProxyBridgeCAOptions,
} from './proxy-bridges/index.js';
import {GeoLite2, Router} from './router/index.js';
import {TunnelServer} from './tunnel-server.js';
import {Web} from './web.js';

const SELF_SIGNED_CERTIFICATE_COMMON_NAME = 'tunnel-server.plug2proxy';

export type SetupOptions = {
  caCertPath: string;
  caKeyPath: string;
};

export async function setup(
  {
    alias,
    tunnel: tunnelServerConfig = {},
    proxy: httpProxyOptions = {},
    ddns: ddnsOptions,
  }: Config,
  {caCertPath, caKeyPath}: SetupOptions,
): Promise<void> {
  let caOptions: TLSProxyBridgeCAOptions | false;

  if (
    httpProxyOptions.refererSniffing ??
    HTTP_PROXY_REFERER_SNIFFING_OPTIONS_DEFAULT
  ) {
    caOptions = await ensureCACertificate(caCertPath, caKeyPath);
  } else {
    caOptions = false;
  }

  const geolite2 = new GeoLite2();

  const router = new Router(geolite2);

  const tunnelServer = new TunnelServer(router, {
    alias,
    ...('cert' in tunnelServerConfig && 'key' in tunnelServerConfig
      ? tunnelServerConfig
      : {
          ...tunnelServerConfig,
          ...(await getSelfSignedCertificate(
            SELF_SIGNED_CERTIFICATE_COMMON_NAME,
          )),
        }),
  });

  const tlsProxyBridge = new TLSProxyBridge(tunnelServer, router, {
    ca: caOptions,
  });

  const netProxyBridge = new NetProxyBridge(tunnelServer, router);

  const web = new Web({
    caCertPath: caOptions ? caCertPath : undefined,
  });

  new HTTPProxy(
    tunnelServer,
    tlsProxyBridge,
    netProxyBridge,
    web,
    httpProxyOptions,
  );

  if (ddnsOptions) {
    new DDNS(ddnsOptions);
  }
}
