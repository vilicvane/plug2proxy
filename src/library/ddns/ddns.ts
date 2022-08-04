import ms from 'ms';
import PublicIP from 'public-ip';
import * as x from 'x-value';

import type {IDDNSProvider} from './ddns-provider';
import {ProviderDDNSOptions, createDDNSProvider} from './providers';

const CHECK_INTERVAL_DEFAULT = x.Integer.satisfies(ms('5s'));

const CHECK_TIMEOUT = ms('5m');

export const DDNSOptions = x.intersection(
  x.object({
    checkInterval: x.integerRange({min: 1000}).optional(),
  }),
  ProviderDDNSOptions,
);

export type DDNSOptions = x.TypeOf<typeof DDNSOptions>;

export class DDNS {
  private provider: IDDNSProvider;

  private checkInterval: number;

  private ip: string | undefined;

  constructor({
    checkInterval = CHECK_INTERVAL_DEFAULT,
    ...options
  }: DDNSOptions) {
    this.provider = createDDNSProvider(options);

    this.checkInterval = checkInterval;

    this.checkAndUpdate();
  }

  private checkAndUpdate(): void {
    Promise.race([
      this._checkAndUpdate(),
      new Promise((_resolve, reject) =>
        setTimeout(
          () => reject(new Error('DDNS check and update timed out')),
          CHECK_TIMEOUT,
        ),
      ),
    ])
      .catch(console.error)
      .finally(() =>
        setTimeout(() => this.checkAndUpdate(), this.checkInterval),
      );
  }

  private async _checkAndUpdate(): Promise<void> {
    let ip = await PublicIP.v4({
      onlyHttps: true,
    });

    if (this.ip === ip) {
      return;
    }

    await this.provider.update(ip);

    this.ip = ip;

    console.info(`[ddns] public ip ${ip} (${this.provider.name}).`);
  }
}
