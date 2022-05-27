#!/usr/bin/env node

import * as Path from 'path';

import main, {BACKGROUND} from 'main-function';
import * as x from 'x-value';

import {In, Out, Router, RouterOptions} from '../library';

const Config = x
  .union(
    x.object({
      mode: x.literal('in'),
      server: In.ServerOptions.optional(),
      proxy: In.ProxyOptions.optional(),
    }),
    x.object({
      mode: x.literal('out'),
      router: RouterOptions.optional(),
      clients: x.array(Out.ClientOptions),
    }),
  )
  .exact();

type Config = x.TypeOf<typeof Config>;

main(async ([configModulePath]) => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports,@typescript-eslint/no-var-requires
  const config = Config.satisfies(require(Path.resolve(configModulePath)));

  if (config.mode === 'in') {
    const inServer = new In.Server(config.server ?? {});
    const _inProxy = new In.Proxy(inServer, config.proxy ?? {});
  } else {
    const router = new Router(config.router ?? {});

    for (let [index, clientOptions] of config.clients.entries()) {
      const _outClient = new Out.Client(
        router,
        clientOptions,
        index.toString(),
      );
    }
  }

  await BACKGROUND;
});
