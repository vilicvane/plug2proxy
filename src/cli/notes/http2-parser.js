import {readFile} from 'fs/promises';

import SPDYTransport from 'spdy-transport';

const http2Buffer = await readFile('http2-stream.bin');

const pool = SPDYTransport.protocol.http2.compressionPool.create();

const parser = SPDYTransport.protocol.http2.parser.create({});

parser.setCompression(pool.get());

// const through = new PassThrough();

parser.on('data', console.log);

parser.end(http2Buffer);
