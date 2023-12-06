import * as x from 'x-value';

import type {DDNSType, IDDNSProvider} from '../ddns-provider.js';

import {
  AliCloudDDNSOptions,
  AliCloudDDNSProvider,
} from './alicloud-ddns-provider.js';
import {
  CloudflareDDNSOptions,
  CloudflareDDNSProvider,
} from './cloudflare-ddns-provider.js';

export const ProviderDDNSOptions = x.union([
  CloudflareDDNSOptions,
  AliCloudDDNSOptions,
]);

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

export * from './alicloud-ddns-provider.js';
export * from './cloudflare-ddns-provider.js';
