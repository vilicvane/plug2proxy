import {Out} from '../library/index.js';

export function setupOut({alias, tunnels: tunnelConfigs}: Out.Config): void {
  let lastIdNumber = 0;

  for (const {
    replicas = Out.TUNNEL_CONFIG_REPLICAS_DEFAULT,
    ...tunnelConfig
  } of tunnelConfigs) {
    for (let i = 0; i < replicas; i++) {
      new Out.Tunnel(++lastIdNumber as Out.TunnelId, {
        alias,
        ...tunnelConfig,
      });
    }
  }
}
