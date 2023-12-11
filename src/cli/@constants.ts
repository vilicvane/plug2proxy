import {join, resolve} from 'path';

export const DATA_DIR = resolve('plug2proxy');

export const CA_CERT_PATH = join(DATA_DIR, 'ca.crt');
export const CA_KEY_PATH = join(DATA_DIR, 'ca.key');

export const GEOLITE2_PATH = join(DATA_DIR, 'geolite2.mmdb');
