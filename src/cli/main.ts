import {readFile} from 'fs/promises';

import {In, Router} from '../library/index.js';

const router = new Router();

const proxy = new In.HTTPProxy(router, {
  host: '',
  port: 8888,
  ca: {
    cert: await readFile('plug2proxy-ca.crt', 'utf8'),
    key: await readFile('plug2proxy-ca.key', 'utf8'),
  },
});

// const http2Buffer = await readFile('http2-stream.bin');
