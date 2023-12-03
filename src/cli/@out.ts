import {Out} from '../library/index.js';

export function setupOut({tunnels: tunnelConfigs}: Out.Config): void {
  for (const [index, tunnelConfig] of tunnelConfigs.entries()) {
    new Out.Tunnel((index + 1) as Out.TunnelId, tunnelConfig);
  }
}
