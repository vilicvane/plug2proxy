import {readFile} from 'fs/promises';

import {In, Out} from '../library/index.js';

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

const tunnel = new Out.Tunnel({
  authority: 'https://172.19.32.1:8443',
  rejectUnauthorized: false,
  config: {
    routeMatchOptions: {
      include: [
        {
          type: 'domain',
          match: 'baidu.com',
        },
        {
          type: 'geoip',
          match: 'CN',
        },
      ],
      exclude: [],
    },
  },
});

// const http2Buffer = await readFile('http2-stream.bin');
