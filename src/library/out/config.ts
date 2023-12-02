import * as x from 'x-value';

export const Config = x.object({
  mode: x.literal('out'),
});

export type Config = x.TypeOf<typeof Config>;
