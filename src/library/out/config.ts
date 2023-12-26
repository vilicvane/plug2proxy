import * as x from 'x-value';

import {RouteMatchOptions} from '../router.js';
import {Port} from '../x.js';

export const TUNNEL_CONFIG_REPLICAS_DEFAULT = 1;

const TunnelConfig = x.object({
  alias: x.string.optional(),
  host: x.string,
  port: Port.optional(),
  password: x.string.optional(),
  rejectUnauthorized: x.boolean.optional(),
  match: RouteMatchOptions.optional(),
  replicas: x.number.optional(),
});

export const Config = x.intersection([
  x.object({
    mode: x.literal('out'),
    alias: x.string.optional(),
  }),
  x.union([
    x.object({
      tunnel: TunnelConfig,
    }),
    x.object({
      tunnels: x.array(TunnelConfig),
    }),
  ]),
]);

export type Config = x.TypeOf<typeof Config>;
