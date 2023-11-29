import {readFile} from 'fs/promises';

import {In} from '../library/index.js';

const geolite2 = new In.GeoLite2({});

const router = new In.Router(geolite2);

router.register('0' as In.TunnelCandidateId, {
  include: [
    // {
    //   type: 'domain',
    //   match: 'baidu.com',
    //   negate: true,
    // },
    {
      type: 'geoip',
      match: 'CN',
    },
  ],
  exclude: [],
});

console.log(await router.route('47.91.217.35'));

const tlsProxy = new In.TLSProxy(router, {
  ca: {
    cert: await readFile('plug2proxy-ca.crt', 'utf8'),
    key: await readFile('plug2proxy-ca.key', 'utf8'),
  },
});

const proxy = new In.HTTPProxy(
  tlsProxy,
  In.HTTPProxyOptions.nominalize({
    host: '',
    port: 8888,
  }),
);

// const http2Buffer = await readFile('http2-stream.bin');
