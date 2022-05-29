import AliCloudDNSClient, {
  AddDomainRecordRequest,
  DescribeDomainRecordsRequest,
  UpdateDomainRecordRequest,
} from '@alicloud/alidns20150109';
import * as AliCloudOpenAPIClient from '@alicloud/openapi-client';
import * as x from 'x-value';

import type {IDDNSProvider} from '../ddns-provider';

const ENDPOINT_DEFAULT = 'alidns.cn-shenzhen.aliyuncs.com';

export const AliCloudDDNSOptions = x.object({
  provider: x.literal('alicloud'),
  endpoint: x.string.optional(),
  accessKeyId: x.string,
  accessKeySecret: x.string,
  domain: x.string,
  record: x.string,
});

export type AliCloudDDNSOptions = x.TypeOf<typeof AliCloudDDNSOptions>;

export class AliCloudDDNSProvider implements IDDNSProvider {
  readonly name = 'alicloud';

  private client: AliCloudDNSClient;

  private domain: string;
  private recordName: string;

  private recordId: string | undefined;

  constructor({
    accessKeyId,
    accessKeySecret,
    endpoint = ENDPOINT_DEFAULT,
    domain,
    record: recordName,
  }: AliCloudDDNSOptions) {
    let config = new AliCloudOpenAPIClient.Config({
      accessKeyId,
      accessKeySecret,
    });

    config.endpoint = endpoint;

    this.client = new AliCloudDNSClient(config);

    this.domain = domain;

    if (recordName.endsWith(`.${domain}`)) {
      recordName = recordName.slice(0, -domain.length - 1);
    }

    this.recordName = recordName;
  }

  async update(ip: string): Promise<void> {
    const client = this.client;

    let domain = this.domain;
    let recordName = this.recordName;

    let recordId = this.recordId;

    if (!recordId) {
      let existingRecord = (
        await client.describeDomainRecords(
          new DescribeDomainRecordsRequest({
            domainName: domain,
            keyWord: recordName,
            searchMode: 'exact',
          }),
        )
      ).body.domainRecords?.record?.find(record => record.RR === recordName);

      if (existingRecord) {
        this.recordId = recordId = existingRecord.recordId;

        if (existingRecord.value === ip) {
          return;
        }
      }
    }

    let recordPartial = {
      RR: recordName,
      type: 'A',
      value: ip,
    };

    if (recordId) {
      await client.updateDomainRecord(
        new UpdateDomainRecordRequest({
          recordId,
          ...recordPartial,
        }),
      );
    } else {
      this.recordId = (
        await client.addDomainRecord(
          new AddDomainRecordRequest({
            domainName: domain,
            ...recordPartial,
          }),
        )
      ).body.recordId;
    }
  }
}
