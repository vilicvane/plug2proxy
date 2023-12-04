import Chalk from 'chalk';
import Express from 'express';
import * as x from 'x-value';

import {Logs} from '../@log/index.js';

export const WEB_HOSTNAME = 'plug2proxy';

const CA_FILENAME = 'ca.crt';

export const WebOptions = x.object({
  caCertPath: x.string.optional(),
});

export type WebOptions = x.TypeOf<typeof WebOptions>;

export class Web {
  readonly app: Express.Express;

  constructor({caCertPath}: WebOptions) {
    const app = Express();

    app.use((request, _response, next) => {
      Logs.info('web', request.method, request.url);

      next();
    });

    if (caCertPath !== undefined) {
      console.info(
        `Plug2Proxy CA enabled, please download and install the CA certificate from ${Chalk.green(
          `http://${WEB_HOSTNAME}/${CA_FILENAME}`,
        )} (after configuring Plug2Proxy as the proxy server).`,
      );

      app.get(`/${CA_FILENAME}`, (_request, response) => {
        response.sendFile(caCertPath);
      });
    }

    app.all('*', (_request, response) => {
      response.send(`\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Plug2Proxy</title>
</head>
<body>
  <h1>Plug2Proxy</h1>
  <p>Plug2Proxy is running.</p>
  <ul>
    <li><a href="/${CA_FILENAME}">Download CA certificate</a></li>
  </ul>
</body>
`);
    });

    this.app = app;
  }
}
