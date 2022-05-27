import * as IPMatching from 'ip-matching';
import * as x from 'x-value';

export const Port = x.integerRange<'port'>({min: 1, max: 65535});

export const IPMatchPattern = x.string.refine<'ip match pattern'>(value => {
  IPMatching.getMatch(value);
});

export const IPPattern = x.string.refine<'ip pattern'>(value => {
  let ip = IPMatching.getIP(value);

  if (ip === null) {
    throw new TypeError('Invalid IP address');
  }
});
