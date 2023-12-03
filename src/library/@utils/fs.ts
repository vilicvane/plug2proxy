import type {Stats} from 'fs';
import {stat} from 'fs/promises';

export function gentleStat(path: string): Promise<Stats | undefined> {
  return stat(path).catch(() => undefined);
}
