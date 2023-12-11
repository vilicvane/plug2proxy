import type {Config} from './config.js';
import {TUNNEL_CONFIG_REPLICAS_DEFAULT} from './config.js';
import type {TunnelId} from './tunnel.js';
import {Tunnel} from './tunnel.js';

export function setup({alias, tunnels: tunnelConfigs}: Config): void {
  let lastIdNumber = 0;

  for (const {
    replicas = TUNNEL_CONFIG_REPLICAS_DEFAULT,
    ...tunnelConfig
  } of tunnelConfigs) {
    for (let i = 0; i < replicas; i++) {
      new Tunnel(++lastIdNumber as TunnelId, {
        alias,
        ...tunnelConfig,
      });
    }
  }
}
