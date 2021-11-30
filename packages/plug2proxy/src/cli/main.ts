#!/usr/bin/env node

import * as Path from 'path';

import main, {BACKGROUND} from 'main-function';

import {In, Out, Router, RouterOptions} from '../library';

type Config =
  | {
      mode: 'in';
      server: In.ServerOptions;
      proxy: In.ProxyOptions;
    }
  | {
      mode: 'out';
      router: RouterOptions;
      clients: Out.ClientOptions[];
    };

main(async ([configModulePath]) => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports,@typescript-eslint/no-var-requires
  const config: Config = require(Path.resolve(configModulePath));

  if (config.mode === 'in') {
    const inServer = new In.Server(config.server);
    const _inProxy = new In.Proxy(inServer, config.proxy);
  } else {
    const router = new Router(config.router);

    for (let clientOptions of config.clients) {
      const _outClient = new Out.Client(router, clientOptions);
    }
  }

  await BACKGROUND;
});
