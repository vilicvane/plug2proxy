import {readFile} from 'fs/promises';

import {identifier} from 'spdy-transport';

import {In} from '../library/index.js';

// const proxy = new In.HTTPProxy({
//   host: '',
//   port: 8888,
//   ca: {
//     cert: await readFile('plug2proxy-ca.crt', 'utf8'),
//     key: await readFile('plug2proxy-ca.key', 'utf8'),
//   },
// });

const http2Buffer = await readFile('http2-stream.bin');

const x = spdy;
