import type {DnsRecord} from 'cloudflare';
import Cloudflare from 'cloudflare';
import * as x from 'x-value';

import type {IDDNSProvider} from '../ddns-provider';

export const CloudflareDDNSOptions = x.object({
  provider: x.literal('cloudflare'),
  token: x.string,
  zone: x.string,
  record: x.object({
    name: x.string,
  }),
});

export type CloudflareDDNSOptions = x.TypeOf<typeof CloudflareDDNSOptions>;

export class CloudflareDDNSProvider implements IDDNSProvider {
  private cloudflare: Cloudflare;

  constructor(private options: CloudflareDDNSOptions) {
    this.cloudflare = new Cloudflare({
      token: options.token,
    });
  }

  async update(ip: string): Promise<void> {
    const DNSRecords = this.cloudflare.dnsRecords;

    let {
      zone: zoneId,
      record: {name},
    } = this.options;

    let existingRecord = (
      (await DNSRecords.browse(zoneId)) as DNSRecordsBrowseResponse
    ).result.find(record => record.name === name);

    let record: DnsRecord = {
      type: 'A',
      name,
      content: ip,
      ttl: 1,
    };

    if (existingRecord) {
      if (existingRecord.content !== ip) {
        await DNSRecords.edit(zoneId, existingRecord.id, record);
      }
    } else {
      await DNSRecords.add(zoneId, record);
    }
  }
}

interface DNSRecordsBrowseResponse {
  result: {
    id: string;
    name: string;
    content: string;
  }[];
}
