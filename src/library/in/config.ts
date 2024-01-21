import * as x from 'x-value';
import * as xn from 'x-value/node';

import {RouteMatchRule} from '../router.js';
import {ListeningHost, Port} from '../x.js';

import {DDNSOptions} from './ddns/index.js';
import {HTTPProxyRefererSniffingOptions} from './http-proxy.js';

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
  refererSniffing: x
    .union([HTTPProxyRefererSniffingOptions, x.boolean])
    .optional(),
});

export const Config = x.intersection([
  x.object({
    mode: x.literal('in'),
    alias: x.string.optional(),
    tunnel: TunnelServerConfig.optional(),
    direct: x.array(RouteMatchRule).optional(),
    ddns: DDNSOptions.optional(),
  }),
  x.union([
    x.object({
      proxy: HTTPProxyConfig,
    }),
    x.object({
      proxies: x.array(HTTPProxyConfig),
    }),
    x.object({}),
  ]),
]);

export type Config = x.TypeOf<typeof Config>;
