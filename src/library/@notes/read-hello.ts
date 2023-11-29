import {readFile} from 'fs/promises';
import {createServer} from 'net';
import {PassThrough} from 'stream';
import {TLSSocket, createSecureContext} from 'tls';

import {readTlsClientHello} from 'read-tls-client-hello';

const server = createServer(async socket => {
  const through = new PassThrough();

  const helloChunks: Buffer[] = [];

  const onHelloData = (data: Buffer) => {
    helloChunks.push(data);
    through.write(data);
  };

  socket.on('data', onHelloData);

  const data = await readTlsClientHello(through);

  console.log(data);

  socket.off('data', onHelloData);

  socket.pause();

  const hello = Buffer.concat(helloChunks);

  console.log(hello.length);

  socket.unshift(hello);

  const tlsSocket = new TLSSocket(socket, {
    isServer: true,
    ALPNProtocols: ['h2'],
    secureContext: createSecureContext({
      cert: await readFile('172.19.32.1.pem', 'utf8'),
      key: await readFile('172.19.32.1-key.pem', 'utf8'),
    }),
  });

  tlsSocket.on('session', () => {
    console.log('secure connect');
  });
  tlsSocket.on('keylog', data => console.log(data.toString()));

  // socket.resume();
}).listen(8888);
