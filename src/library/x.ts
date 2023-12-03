import IPMatching from 'ip-matching';
import * as x from 'x-value';

export const IPMatchPattern = x.string.refined<'ip match pattern'>(value => {
  IPMatching.getMatch(value);
  return value;
});

export const IPPattern = x.string.refined<'ip pattern'>(value => {
  const ip = IPMatching.getIP(value);

  if (ip === null) {
    throw new TypeError('Invalid IP address');
  }

  return value;
});

export const ListeningHost = x.union([IPPattern, x.literal('')]);

export type ListeningHost = x.TypeOf<typeof ListeningHost>;

export const Port = x.integerRange<'port'>({min: 1, max: 65535});

export type Port = x.TypeOf<typeof Port>;
