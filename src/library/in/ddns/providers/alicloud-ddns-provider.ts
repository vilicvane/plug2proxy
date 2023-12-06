import {
  AddDomainRecordRequest,
  default as AliCloudDNSClient,
  DescribeDomainRecordsRequest,
  UpdateDomainRecordRequest,
} from '@alicloud/alidns20150109';
import * as AliCloudOpenAPIClient from '@alicloud/openapi-client';
import * as x from 'x-value';

import type {DDNSType, IDDNSProvider} from '../ddns-provider.js';

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

  private client: AliCloudDNSClient.default;

  private domain: string;
  private recordName: string;

  constructor(
    readonly type: DDNSType,
    {
      accessKeyId,
      accessKeySecret,
      endpoint = ENDPOINT_DEFAULT,
      domain,
      record: recordName,
    }: AliCloudDDNSOptions,
  ) {
    const config = new AliCloudOpenAPIClient.Config({
      accessKeyId,
      accessKeySecret,
    });

    config.endpoint = endpoint;

    this.client = new AliCloudDNSClient.default(config);

    this.domain = domain;

    if (recordName.endsWith(`.${domain}`)) {
      recordName = recordName.slice(0, -domain.length - 1);
    }

    this.recordName = recordName;
  }

  async update(ip: string): Promise<void> {
    const client = this.client;

    const type = this.type;

    const domain = this.domain;
    const recordName = this.recordName;

    const existingRecord = (
      await client.describeDomainRecords(
        new DescribeDomainRecordsRequest({
          domainName: domain,
          keyWord: recordName,
          searchMode: 'exact',
        }),
      )
    ).body.domainRecords?.record?.find(record => {
      switch (record.type) {
        case 'A':
        case 'AAAA':
          return record.RR === recordName;
        default:
          return false;
      }
    });

    if (
      existingRecord &&
      existingRecord.type === type &&
      existingRecord.value === ip
    ) {
      return;
    }

    const recordPartial = {
      RR: recordName,
      type,
      value: ip,
    };

    if (existingRecord) {
      await client.updateDomainRecord(
        new UpdateDomainRecordRequest({
          recordId: existingRecord.recordId,
          ...recordPartial,
        }),
      );
    } else {
      await client.addDomainRecord(
        new AddDomainRecordRequest({
          domainName: domain,
          ...recordPartial,
        }),
      );
    }
  }
}
