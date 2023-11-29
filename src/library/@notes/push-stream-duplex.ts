import {readFile} from 'fs/promises';
import {connect, createSecureServer, createServer} from 'http2';

const server = createSecureServer({
  cert: await readFile('172.19.32.1.pem', 'utf8'),
  key: await readFile('172.19.32.1-key.pem', 'utf8'),
})
  .on('stream', (stream, headers) => {
    console.log({headers});

    stream.pushStream({}, (error, pushStream) => {
      pushStream.respond({':status': 200});

      setTimeout(() => {
        pushStream.write('hello');
      }, 1000);

      // pushStream.on('data', data => {
      //   console.log(data.toString());
      // });
    });
  })
  .listen(8666, () => {
    connect(
      'https://172.19.32.1:8666',
      {
        rejectUnauthorized: false,
      },
      session => {
        session.request({}, {endStream: true});
      },
    ).on('stream', stream => {
      stream.on('data', data => {
        console.log(data.toString());
      });

      // stream.write('world');
    });
  });
