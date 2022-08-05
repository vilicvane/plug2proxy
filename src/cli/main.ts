#!/usr/bin/env node

import * as Path from 'path';

import main, {BACKGROUND} from 'main-function';
import * as x from 'x-value';

import {DDNS, DDNSOptions, In, Out, Router, RouterOptions} from '../library';

const Config = x
  .union(
    x.object({
      mode: x.literal('in'),
      ddns: DDNSOptions.optional(),
      server: In.ServerOptions.optional(),
      proxy: In.ProxyOptions.optional(),
    }),
    x.object({
      mode: x.literal('out'),
      label: x.string.optional(),
      router: RouterOptions.optional(),
      clients: x.array(Out.ClientOptions),
    }),
  )
  .exact();

main(async ([configModulePath]) => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports,@typescript-eslint/no-var-requires
  const config = Config.satisfies(require(Path.resolve(configModulePath)));

  if (config.mode === 'in') {
    if (config.ddns) {
      const _ddns = new DDNS(config.ddns);
    }

    const inServer = new In.Server(config.server ?? {});
    const _inProxy = new In.Proxy(inServer, config.proxy ?? {});
  } else {
    const router = new Router(config.router ?? {});

    for (let [
      index,
      {label = index.toString(), ...restClientOptions},
    ] of config.clients.entries()) {
      const _outClient = new Out.Client(config.label, router, {
        label,
        ...restClientOptions,
      });
    }
  }

  await BACKGROUND;
});
