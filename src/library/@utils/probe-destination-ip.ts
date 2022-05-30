import * as TLS from 'tls';

export async function probeDestinationIP(
  host: string,
  port: number,
  timeout: number,
): Promise<string | undefined> {
  let socket = TLS.connect({
    host,
    port,
  });

  return Promise.race([
    new Promise<string | undefined>(resolve => {
      socket
        .on('secureConnect', () => {
          resolve(socket.remoteAddress);
          socket.end();
        })
        .on('error', () => resolve(undefined));
    }),
    new Promise<undefined>(resolve =>
      setTimeout(() => {
        resolve(undefined);

        if (socket.writable) {
          socket.end();
        } else if (!socket.destroyed) {
          socket.destroy();
        }
      }, timeout),
    ),
  ]);
}
