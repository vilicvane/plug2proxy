import {cosmiconfig} from 'cosmiconfig';
import * as x from 'x-value';

import {In, Out} from '../library/index.js';

import {setupIn} from './@in.js';
import {setupOut} from './@out.js';

process.on('warning', warning => {
  console.warn(warning.name); // Print the warning name
  console.warn(warning.message); // Print the warning message
  console.warn(warning.stack); // Print the stack trace
});

const configExplorer = cosmiconfig('p2p');

const configPath = process.argv[2] as string | undefined;

const result =
  configPath === undefined
    ? await configExplorer.search()
    : await configExplorer.load(configPath);

if (!result) {
  console.error('config file not found.');
  process.exit(1);
}

const config = x
  .union([In.Config, Out.Config])
  .exact()
  .satisfies(result?.config);

switch (config.mode) {
  case 'in':
    await setupIn(config);
    break;
  case 'out':
    setupOut(config);
    break;
}
