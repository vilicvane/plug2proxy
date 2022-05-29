import type * as x from 'x-value';

import type {IDDNSProvider} from '../ddns-provider';

import {
  CloudflareDDNSOptions,
  CloudflareDDNSProvider,
} from './cloudflare-ddns-provider';

export const ProviderDDNSOptions = CloudflareDDNSOptions;

export type ProviderDDNSOptions = x.TypeOf<typeof ProviderDDNSOptions>;

export function createDDNSProvider(
  options: ProviderDDNSOptions,
): IDDNSProvider {
  switch (options.provider) {
    case 'cloudflare':
      return new CloudflareDDNSProvider(options);
  }
}

export * from './cloudflare-ddns-provider';
