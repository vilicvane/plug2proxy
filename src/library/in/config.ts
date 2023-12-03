import * as x from 'x-value';

import {HTTPProxyOptions} from './http-proxy.js';
import {TunnelServerOptions} from './tunnel-server.js';

export const CONFIG_CA_DEFAULT = false;

export const Config = x.object({
  mode: x.literal('in'),
  tunnel: TunnelServerOptions.optional(),
  proxy: HTTPProxyOptions.optional(),
  ca: x.boolean.optional(),
});

export type Config = x.TypeOf<typeof Config>;
