import * as x from 'x-value';
import * as xn from 'x-value/node';

import {ListeningHost, Port} from '../x.js';

import {DDNSOptions} from './ddns/index.js';

export const CONFIG_PROXY_CA_DEFAULT = false;

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

const HTTPProxyCAConfig = x.object({
  exclude: x.array(x.string).optional(),
});

const HTTPProxyConfig = x.object({
  host: ListeningHost.optional(),
  port: Port.optional(),
  ca: x.union([HTTPProxyCAConfig, x.boolean]).optional(),
});

export const Config = x.object({
  mode: x.literal('in'),
  alias: x.string.optional(),
  tunnel: TunnelServerConfig.optional(),
  proxy: HTTPProxyConfig.optional(),
  ddns: DDNSOptions.optional(),
});

export type Config = x.TypeOf<typeof Config>;
