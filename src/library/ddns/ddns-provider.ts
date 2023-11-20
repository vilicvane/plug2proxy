import * as x from 'x-value';

export const DDNSType = x.union(x.literal('ipv4'), x.literal('ipv6'));

export type DDNSType = x.TypeOf<typeof DDNSType>;

export interface IDDNSProvider {
  readonly name: string;

  update(ip: string): Promise<void>;
}
