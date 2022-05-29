import type {DnsRecord} from 'cloudflare';
import Cloudflare from 'cloudflare';
import * as x from 'x-value';

import type {IDDNSProvider} from '../ddns-provider';

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

export type CloudflareDDNSOptions = x.TypeOf<typeof CloudflareDDNSOptions>;

export class CloudflareDDNSProvider implements IDDNSProvider {
  readonly name = 'cloudflare';

  private cloudflare: Cloudflare;

  private zoneId: string;
  private recordName: string;

  private recordId: string | undefined;

  constructor({
    token,
    zone: zoneId,
    record: recordName,
  }: CloudflareDDNSOptions) {
    this.cloudflare = new Cloudflare({
      token,
    });

    this.zoneId = zoneId;
    this.recordName = recordName;
  }

  async update(ip: string): Promise<void> {
    const DNSRecords = this.cloudflare.dnsRecords;

    let zoneId = this.zoneId;
    let recordName = this.recordName;

    let recordId = this.recordId;

    if (!recordId) {
      let existingRecord = (
        (await DNSRecords.browse(zoneId)) as DNSRecordsBrowseResponse
      ).result.find(record => record.name === recordName);

      if (existingRecord) {
        this.recordId = recordId = existingRecord.id;

        if (existingRecord.content === ip) {
          return;
        }
      }
    }

    let record: DnsRecord = {
      type: 'A',
      name: recordName,
      content: ip,
      /**
       * 1 stands auto.
       */
      ttl: 1,
    };

    if (recordId) {
      await DNSRecords.edit(zoneId, recordId, record);
    } else {
      this.recordId = (
        (await DNSRecords.add(zoneId, record)) as DNSRecordsAddResponse
      ).result.id;
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

interface DNSRecordsAddResponse {
  result: {
    id: string;
  };
}
