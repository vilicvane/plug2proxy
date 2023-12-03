import * as x from 'x-value';
import * as xn from 'x-value/node';

import {ListeningHost, Port} from '../x.js';

export const CONFIG_CA_DEFAULT = false;

const TunnelServerConfig = x.intersection([
  x.object({
    host: ListeningHost.optional(),
    port: Port.optional(),
    password: x.string.optional(),
  }),
  x.union([
    x.object({
      cert: x.union([x.string, xn.Buffer]),
      key: x.union([x.string, xn.Buffer]),
    }),
    x.object({}),
  ]),
]);

const HTTPProxyConfig = x.object({
  host: ListeningHost.optional(),
  port: Port.optional(),
});

export const Config = x.object({
  mode: x.literal('in'),
  tunnel: TunnelServerConfig.optional(),
  proxy: HTTPProxyConfig.optional(),
  ca: x.boolean.optional(),
});

export type Config = x.TypeOf<typeof Config>;
