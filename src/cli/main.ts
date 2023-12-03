import {readFile} from 'fs/promises';

import {cosmiconfig} from 'cosmiconfig';
import * as x from 'x-value';

import type {In} from '../library/index.js';
import {Out} from '../library/index.js';

import {setupIn} from './@in.js';
import {setupOut} from './@out.js';

// const configExplorer = cosmiconfig('p2p');

// const configPath = process.argv[2] as string | undefined;

// const result =
//   configPath === undefined
//     ? await configExplorer.search()
//     : await configExplorer.load(configPath);

// if (!result) {
//   console.error('config file not found.');
//   process.exit(1);
// }

// const config = x.union([In.Config, Out.Config]).satisfies(result?.config);

// switch (config.mode) {
//   case 'in':
//     setupIn(config);
//     break;
//   case 'out':
//     setupOut(config);
//     break;
// }

if (process.argv.includes('--in')) {
  await setupIn({
    ca: true,
  } as In.Config);
} else if (process.argv.includes('--out')) {
  const tunnel = new Out.Tunnel(1 as Out.TunnelId, {
    authority: 'https://172.19.32.1:8443',
    rejectUnauthorized: false,
    config: {
      routeMatchOptions: {
        include: [
          {
            type: 'geoip',
            match: 'CN',
            negate: true,
          },
        ],
        exclude: [],
      },
    },
  });
}

// const http2Buffer = await readFile('http2-stream.bin');
