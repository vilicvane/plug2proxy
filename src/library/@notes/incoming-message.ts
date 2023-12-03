import {IncomingMessage} from 'http';
import {createServer} from 'net';

createServer(socket => {
  const request = new IncomingMessage(socket);
}).listen(8899);
