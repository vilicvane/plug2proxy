import * as x from 'x-value';

import {RouteMatchOptions} from '../router.js';
import {Port} from '../x.js';

const TunnelConfig = x.object({
  host: x.string,
  port: Port.optional(),
  rejectUnauthorized: x.boolean.optional(),
  match: RouteMatchOptions.optional(),
  alias: x.string.optional(),
});

export const Config = x.object({
  mode: x.literal('out'),
  tunnels: x.array(TunnelConfig),
});

export type Config = x.TypeOf<typeof Config>;
