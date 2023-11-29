import * as x from 'x-value';

import {IPMatchPattern} from './x.js';

export const ROUTE_MATCH_PRIORITY_DEFAULT = 0;

export const ROUTE_MATCH_RULE_NEGATE_DEFAULT = false;

export const RouteMatchIPRuleMatchPattern = x.union([
  x.literal('loopback'),
  x.literal('private'),
  IPMatchPattern,
]);

export const RouteMatchRule = x.intersection([
  x.union([
    x.object({
      type: x.literal('ip'),
      match: x
        .union([
          RouteMatchIPRuleMatchPattern,
          x.array(RouteMatchIPRuleMatchPattern),
        ])
        .nominal({
          description:
            '支持 "loopback"、"private" 或类似 "10.1.2.3"、"10.0.0.0/24" 的 IP 地址/地址段。',
        }),
    }),
    x.object({
      type: x.literal('geoip'),
      match: x.union([x.string, x.array(x.string)]).nominal({
        description:
          '支持 MaxMind GeoLite2 数据中的 country.iso_code 字段，如 "CN"。需要下载并配置数据库文件，`geoIPDatabase` 参数。',
      }),
    }),
    x.object({
      type: x.literal('domain'),
      match: x.union([x.string, x.array(x.string)]).nominal({
        description:
          '域名，支持 micromatch 格式。如 ["baidu.com", "*.baidu.com"]。',
      }),
    }),
  ]),
  x.object({
    negate: x.boolean
      .nominal({
        description: '是否反向匹配。',
      })
      .optional(),
  }),
]);

export type RouteMatchRule = x.TypeOf<typeof RouteMatchRule>;

export const RouteMatchIncludeRule = x.intersection([
  RouteMatchRule,
  x.object({
    priority: x.number.optional(),
  }),
]);

export type RouteMatchIncludeRule = x.TypeOf<typeof RouteMatchIncludeRule>;

export const RouteMatchOptions = x.object({
  include: x.array(RouteMatchIncludeRule).optional(),
  exclude: x.array(RouteMatchRule).optional(),
  priority: x.number.optional(),
});

export type RouteMatchOptions = x.TypeOf<typeof RouteMatchOptions>;
