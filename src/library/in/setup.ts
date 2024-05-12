import {ensureCACertificate, getSelfSignedCertificate} from './certificate.js';
import type {Config} from './config.js';
import {DDNS} from './ddns/index.js';
import {
  HTTPProxy,
  HTTP_PROXY_REFERER_SNIFFING_OPTIONS_DEFAULT,
} from './http-proxy.js';
import {NetProxyBridge, TLSProxyBridge} from './proxy-bridges/index.js';
import {GeoLite2, Router} from './router/index.js';
import {TunnelServer} from './tunnel-server.js';
import {Web} from './web.js';

const SELF_SIGNED_CERTIFICATE_COMMON_NAME = 'tunnel-server.plug2proxy';

export type SetupOptions = {
  caCertPath: string;
  caKeyPath: string;
  geolite2Path: string;
};

export async function setup(
  {
    alias,
    tunnel: tunnelServerConfig = {},
    ddns: ddnsOptions,
    direct,
    ...rest
  }: Config,
  {caCertPath, caKeyPath, geolite2Path}: SetupOptions,
): Promise<void> {
  const ca = await ensureCACertificate(caCertPath, caKeyPath);

  const geolite2 = new GeoLite2({path: geolite2Path});

  const router = new Router(geolite2, direct);

  const tunnelServer = new TunnelServer(router, {
    alias,
    ...('cert' in tunnelServerConfig && 'key' in tunnelServerConfig
      ? tunnelServerConfig
      : {
          ...tunnelServerConfig,
          ...(await getSelfSignedCertificate(
            ca.cert,
            ca.key,
            SELF_SIGNED_CERTIFICATE_COMMON_NAME,
          )),
        }),
  });

  geolite2.tunnelServer = tunnelServer;

  const httpProxyOptionsArray =
    'proxy' in rest ? [rest.proxy] : 'proxies' in rest ? rest.proxies : [{}];

  for (const [index, httpProxyOptions] of httpProxyOptionsArray.entries()) {
    const refererSniffing =
      httpProxyOptions.refererSniffing ??
      HTTP_PROXY_REFERER_SNIFFING_OPTIONS_DEFAULT;

    const tlsProxyBridge = refererSniffing
      ? new TLSProxyBridge(tunnelServer, router, {ca})
      : undefined;

    const netProxyBridge = new NetProxyBridge(tunnelServer, router);

    const web = new Web({
      caCertPath: refererSniffing ? caCertPath : undefined,
    });

    new HTTPProxy(
      index,
      netProxyBridge,
      tlsProxyBridge,
      router,
      web,
      httpProxyOptions,
    );
  }

  if (ddnsOptions) {
    new DDNS(ddnsOptions);
  }
}
