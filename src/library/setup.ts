import * as Net from 'net';

export function setup(): void {
  Net.setDefaultAutoSelectFamilyAttemptTimeout(1000);
}
