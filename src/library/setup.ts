import {setMaxListeners} from 'events';
import * as Net from 'net';

export function setup(): void {
  if (Net.setDefaultAutoSelectFamilyAttemptTimeout) {
    Net.setDefaultAutoSelectFamilyAttemptTimeout(1000);
  }

  setMaxListeners(20);
}
