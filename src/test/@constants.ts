import {dirname, join} from 'path';
import {fileURLToPath} from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

export const TEST_RESOURCE_DIR = join(__dirname, '../../test');
