import {readFile} from 'fs/promises';

import {In, Out} from '../library/index.js';

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
