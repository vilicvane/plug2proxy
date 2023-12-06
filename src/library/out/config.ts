import * as x from 'x-value';

import {RouteMatchOptions} from '../router.js';
import {Port} from '../x.js';

const TunnelConfig = x.object({
  alias: x.string.optional(),
  host: x.string,
  port: Port.optional(),
  password: x.string.optional(),
  rejectUnauthorized: x.boolean.optional(),
  match: RouteMatchOptions.optional(),
});

export const Config = x.object({
  mode: x.literal('out'),
  alias: x.string.optional(),
  tunnels: x.array(TunnelConfig),
});

export type Config = x.TypeOf<typeof Config>;
