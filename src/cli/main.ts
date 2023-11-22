import {readFile} from 'fs/promises';

import {In} from '../library/index.js';

const proxy = new In.HTTPProxy({
  host: '',
  port: 8888,
  ca: {
    cert: await readFile('plug2proxy-ca.crt', 'utf8'),
    key: await readFile('plug2proxy-ca.key', 'utf8'),
  },
});
