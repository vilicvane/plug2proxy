import {readFile} from 'fs/promises';

import {cosmiconfig} from 'cosmiconfig';
import * as x from 'x-value';

import {In, Out} from '../library/index.js';

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
  const geolite2 = new In.GeoLite2({});

  const router = new In.Router(geolite2);

  const tunnelServer = new In.TunnelServer(router, {
    cert: await readFile('172.19.32.1.pem', 'utf8'),
    key: await readFile('172.19.32.1-key.pem', 'utf8'),
  });

  const tlsProxy = new In.TLSProxy(tunnelServer, router, {
    ca: {
      cert: await readFile('plug2proxy-ca.crt', 'utf8'),
      key: await readFile('plug2proxy-ca.key', 'utf8'),
    },
  });

  const proxy = new In.HTTPProxy(
    tunnelServer,
    tlsProxy,
    In.HTTPProxyOptions.nominalize({
      host: '',
      port: 8888,
    }),
  );
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
