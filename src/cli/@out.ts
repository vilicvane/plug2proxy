import {Out} from '../library/index.js';

export function setupOut({alias, tunnels: tunnelConfigs}: Out.Config): void {
  for (const [index, tunnelConfig] of tunnelConfigs.entries()) {
    new Out.Tunnel((index + 1) as Out.TunnelId, {
      alias,
      ...tunnelConfig,
    });
  }
}
