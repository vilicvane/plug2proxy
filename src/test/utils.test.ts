// import {createReadStream} from 'fs';
// import {join} from 'path';
// import {PassThrough} from 'stream';
// import {buffer} from 'stream/consumers';

// import {readHTTPRequestStreamHeaders} from '../library/@utils/index.js';

// import {TEST_RESOURCE_DIR} from './@constants.js';

// test('read http2 headers', async () => {
//   const stream = createReadStream(join(TEST_RESOURCE_DIR, 'http2-stream.bin'));

//   const headerMap = await readHTTPRequestStreamHeaders(stream);

//   expect(headerMap).toMatchInlineSnapshot(`
// Map {
//   ":method" => "GET",
//   ":path" => "/",
//   ":scheme" => "https",
//   ":authority" => "www.github.com",
//   "user-agent" => "curl/7.81.0",
//   "accept" => "*/*",
// }
// `);

//   expect((await buffer(stream)).length).toMatchInlineSnapshot(`104`);
// });

// test('read http headers', async () => {
//   const stream = new PassThrough();

//   void (async () => {
//     await Promise.resolve();

//     stream.write('GET / HTTP/1.1\r\n');
//     stream.write('Host: www.github.com\r\n');
//     stream.write('User-Agent: curl/7.81.0\r\n');

//     await Promise.resolve();

//     stream.write('Accept: */*\r\n');
//     stream.write('\r\n');

//     stream.end();
//   })();

//   const headerMap = await readHTTPRequestStreamHeaders(stream);

//   expect(headerMap).toMatchInlineSnapshot(`
// Map {
//   "host" => "www.github.com",
//   "user-agent" => "curl/7.81.0",
//   "accept" => "*/*",
// }
// `);

//   expect((await buffer(stream)).length).toMatchInlineSnapshot(`78`);
// });
