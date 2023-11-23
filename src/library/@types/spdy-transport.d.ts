import {Duplex} from 'stream';

declare module 'spdy-transport' {
  namespace SPDYTransport {
    namespace protocol {
      namespace http2 {
        namespace compressionPool {
          type Compression = {
            __nominal: 'compression';
          };

          type CompressionPool = {
            get(): Compression;
          };

          function create(): CompressionPool;
        }

        namespace parser {
          class Parser extends Duplex {
            setCompression(compression: CompressionPool): void;
          }

          function create(options: {}): Parser;
        }
      }
    }
  }

  export default SPDYTransport;
}
