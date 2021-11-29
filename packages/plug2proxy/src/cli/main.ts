#!/usr/bin/env node

import * as Path from 'path';

import main, {BACKGROUND} from 'main-function';

import {
  InProxy,
  InProxyOptions,
  InServer,
  InServerOptions,
  OutClient,
  OutClientOptions,
  Router,
  RouterOptions,
} from '../library';

type Config =
  | {
      mode: 'in';
      server: InServerOptions;
      proxy: InProxyOptions;
    }
  | {
      mode: 'out';
      router: RouterOptions;
      client: OutClientOptions;
    };

main(async ([configModulePath]) => {
  // eslint-disable-next-line @typescript-eslint/no-require-imports,@typescript-eslint/no-var-requires
  const config: Config = require(Path.resolve(configModulePath));

  if (config.mode === 'in') {
    const inServer = new InServer(config.server);
    const _inProxy = new InProxy(inServer, config.proxy);
  } else {
    const router = new Router(config.router);
    const _outClient = new OutClient(router, config.client);
  }

  await BACKGROUND;
});
