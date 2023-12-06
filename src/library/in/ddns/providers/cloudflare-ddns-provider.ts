import type {DnsRecord, DnsRecordWithoutPriority} from 'cloudflare';
import Cloudflare from 'cloudflare';
import * as x from 'x-value';

import type {DDNSType, IDDNSProvider} from '../ddns-provider.js';

export const CloudflareDDNSOptions = x.object({
  provider: x.literal('cloudflare'),
  /**
   * API token.
   */
  token: x.string,
  /**
   * Zone ID.
   */
  zone: x.string,
  /**
   * Full name with domain, e.g.: "*.p2p.example.com"
   */
  record: x.string,
});

Cloudflare;

export type CloudflareDDNSOptions = x.TypeOf<typeof CloudflareDDNSOptions>;

export class CloudflareDDNSProvider implements IDDNSProvider {
  readonly name = 'cloudflare';

  private cloudflare: Cloudflare;

  private zoneId: string;
  private recordName: string;

  constructor(
    readonly type: DDNSType,
    {token, zone: zoneId, record: recordName}: CloudflareDDNSOptions,
  ) {
    this.cloudflare = new Cloudflare({
      token,
    });

    this.zoneId = zoneId;
    this.recordName = recordName;
  }

  async update(ip: string): Promise<void> {
    const DNSRecords = this.cloudflare.dnsRecords;

    const type = this.type;

    const zoneId = this.zoneId;
    const recordName = this.recordName;

    const existingRecord = (await DNSRecords.browse(zoneId)).result?.find(
      (record): record is DnsRecordWithoutPriority => {
        switch (record.type) {
          case 'A':
          case 'AAAA':
            return record.name === recordName;
          default:
            return false;
        }
      },
    );

    if (
      existingRecord &&
      existingRecord.type === type &&
      existingRecord.content === ip
    ) {
      return;
    }

    const record: DnsRecord = {
      type,
      name: recordName,
      content: ip,
      ttl: 1, // auto
    };

    if (existingRecord) {
      await DNSRecords.edit(zoneId, (existingRecord as any).id, record);
    } else {
      await DNSRecords.add(zoneId, record);
    }
  }
}
