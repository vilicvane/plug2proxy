import * as x from 'x-value';

import type {DDNSType, IDDNSProvider} from '../ddns-provider';

import {
  AliCloudDDNSOptions,
  AliCloudDDNSProvider,
} from './alicloud-ddns-provider';
import {
  CloudflareDDNSOptions,
  CloudflareDDNSProvider,
} from './cloudflare-ddns-provider';

export const ProviderDDNSOptions = x.union(
  CloudflareDDNSOptions,
  AliCloudDDNSOptions,
);

export type ProviderDDNSOptions = x.TypeOf<typeof ProviderDDNSOptions>;

export function createDDNSProvider(
  type: DDNSType,
  options: ProviderDDNSOptions,
): IDDNSProvider {
  switch (options.provider) {
    case 'cloudflare':
      return new CloudflareDDNSProvider(type, options);
    case 'alicloud':
      return new AliCloudDDNSProvider(type, options);
  }
}

export * from './cloudflare-ddns-provider';
export * from './alicloud-ddns-provider';
