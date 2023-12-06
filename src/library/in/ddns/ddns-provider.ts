import * as x from 'x-value';

export const DDNSType = x.union([x.literal('A'), x.literal('AAAA')]);

export type DDNSType = x.TypeOf<typeof DDNSType>;

export const IPType = x.union([x.literal('ipv4'), x.literal('ipv6')]);

export type IPType = x.TypeOf<typeof IPType>;

export type IDDNSProvider = {
  readonly name: string;

  update(ip: string): Promise<void>;
};
