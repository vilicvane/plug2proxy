import {cosmiconfig} from 'cosmiconfig';
import * as x from 'x-value';

import {In, Out} from '../library/index.js';

import {CA_CERT_PATH, CA_KEY_PATH, GEOLITE2_PATH} from './@constants.js';
import {setupDebug} from './@debug.js';

setupDebug();

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
    await In.setup(config, {
      caCertPath: CA_CERT_PATH,
      caKeyPath: CA_KEY_PATH,
      geolite2Path: GEOLITE2_PATH,
    });
    break;
  case 'out':
    Out.setup(config);
    break;
}
