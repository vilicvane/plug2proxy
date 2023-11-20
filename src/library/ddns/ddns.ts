import ms from 'ms';
import PublicIP from 'public-ip';
import * as x from 'x-value';

import {DDNSType} from './ddns-provider';
import type {IDDNSProvider} from './ddns-provider';
import {ProviderDDNSOptions, createDDNSProvider} from './providers';

const DDNS_TYPE_DEFAULT = 'ipv4';
const CHECK_INTERVAL_DEFAULT = x.Integer.satisfies(ms('5s'));

const CHECK_TIMEOUT = ms('5m');

export const DDNSOptions = x.intersection(
  x.object({
    type: DDNSType.optional(),
    checkInterval: x.integerRange({min: 1000}).optional(),
  }),
  ProviderDDNSOptions,
);

export type DDNSOptions = x.TypeOf<typeof DDNSOptions>;

export class DDNS {
  private provider: IDDNSProvider;

  private type: DDNSType;
  private checkInterval: number;

  private ip: string | undefined;

  constructor({
    type = DDNS_TYPE_DEFAULT,
    checkInterval = CHECK_INTERVAL_DEFAULT,
    ...options
  }: DDNSOptions) {
    this.provider = createDDNSProvider(type, options);

    this.type = type;
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
    let ip = await PublicIP[this.type === 'ipv4' ? 'v4' : 'v6']({
      onlyHttps: true,
    });

    if (this.ip === ip) {
      return;
    }

    console.info(`[ddns] public ip ${ip} (${this.provider.name}).`);

    await this.provider.update(ip);

    this.ip = ip;
  }
}
