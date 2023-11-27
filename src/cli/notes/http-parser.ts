import {HTTPParser} from 'http-parser-js';

const parser = new HTTPParser('REQUEST');

parser.onHeadersComplete = console.log;

setTimeout(() => {
  parser.execute(
    Buffer.from(
      'GET / HTTP/1.1\r\n' +
        'Host: www.github.com\r\n' +
        'User-Agent: curl/7.81.0\r\n' +
        'Accept: */*\r\n' +
        '\r\n',
    ),
  );
});

// parser.execute(
//   Buffer.from(
//     `\
// POST / HTTP/1.1\r
// Host: example.com\r
// Content-Type: application/json\r
// `,
//   ),
// );

// parser.execute(
//   Buffer.from(
//     `\
// Host2: example.com\r
// Content-Type2: application/json\r
// Host2: example.com\r
// Content-Type2: application/json\r
// Host2: example.com\r
// Content-Type2: application/json\r
// `,
//   ),
// );

// parser.execute(
//   Buffer.from(
//     `\
// X-Surprise: 1\r
// \r
// `,
//   ),
// );

console.log('!!!');
