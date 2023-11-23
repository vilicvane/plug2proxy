declare module 'hpack.js' {
  namespace HPack {
    type Decompressor = {
      write(buffer: Buffer): void;
      execute(): void;
      read(): {name: string; value: string; neverIndex: boolean};
    };

    namespace decompressor {
      function create(options: {table: {size: number}}): Decompressor;
    }
  }

  export default HPack;
}
