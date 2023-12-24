import * as Net from 'net';

export function setup(): void {
  if (Net.setDefaultAutoSelectFamilyAttemptTimeout) {
    Net.setDefaultAutoSelectFamilyAttemptTimeout(1000);
  }
}
