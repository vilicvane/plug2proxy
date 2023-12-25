import {setMaxListeners} from 'events';
import * as Net from 'net';

export function setup(): void {
  if (Net.setDefaultAutoSelectFamilyAttemptTimeout) {
    Net.setDefaultAutoSelectFamilyAttemptTimeout(30_000);
  }

  setMaxListeners(20);
}
