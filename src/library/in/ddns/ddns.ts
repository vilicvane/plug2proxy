import ms from 'ms';
import {publicIpv4, publicIpv6} from 'public-ip';
import * as x from 'x-value';

import {
  IN_DDNS_ERROR_CHECKING_AND_UPDATING,
  IN_DDNS_PUBLIC_IP,
  Logs,
} from '../../@log/index.js';

import type {IDDNSProvider} from './ddns-provider.js';
import {IPType} from './ddns-provider.js';
import {ProviderDDNSOptions, createDDNSProvider} from './providers/index.js';

const IP_TYPE_DEFAULT = 'ipv4';
const CHECK_INTERVAL_DEFAULT = x.Integer.nominalize(ms('5s'));

const CHECK_TIMEOUT = ms('5m');

export const DDNSOptions = x.intersection([
  x.object({
    type: IPType.optional(),
    checkInterval: x.integerRange({min: 1000}).optional(),
  }),
  ProviderDDNSOptions,
]);

export type DDNSOptions = x.TypeOf<typeof DDNSOptions>;

export class DDNS {
  private provider: IDDNSProvider;

  private type: IPType;
  private checkInterval: number;

  private ip: string | undefined;

  constructor({
    type = IP_TYPE_DEFAULT,
    checkInterval = CHECK_INTERVAL_DEFAULT,
    ...options
  }: DDNSOptions) {
    this.provider = createDDNSProvider(type === 'ipv4' ? 'A' : 'AAAA', options);

    this.type = type;
    this.checkInterval = checkInterval;

    this.checkAndUpdate();
  }

  private checkAndUpdate(): void {
    Promise.race([
      this._checkAndUpdate(),
      new Promise((_resolve, reject) =>
        setTimeout(
          () => reject(new Error('DDNS check and update timed out.')),
          CHECK_TIMEOUT,
        ),
      ),
    ])
      .catch(error => {
        Logs.error('ddns', IN_DDNS_ERROR_CHECKING_AND_UPDATING(error));
        Logs.debug('ddns', error);
      })
      .finally(() =>
        setTimeout(() => this.checkAndUpdate(), this.checkInterval),
      );
  }

  private async _checkAndUpdate(): Promise<void> {
    const ip = await (this.type === 'ipv4' ? publicIpv4 : publicIpv6)({
      onlyHttps: true,
    });

    if (this.ip === ip) {
      return;
    }

    Logs.info('ddns', IN_DDNS_PUBLIC_IP(ip, this.provider.name));

    await this.provider.update(ip);

    this.ip = ip;
  }
}
