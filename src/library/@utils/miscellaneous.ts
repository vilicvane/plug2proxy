import {minimatch} from 'minimatch';

export function getErrorCode(error: unknown): string {
  return error instanceof Error
    ? 'code' in error
      ? String(error.code)
      : error.name
    : String(error);
}

export function generateRandomAuthoritySegment(): string {
  return Math.floor(Math.random() * 0xffffffff)
    .toString(16)
    .padStart(8, '0');
}

export function matchHost(host: string, patterns: string[]): boolean {
  return patterns.some(pattern => matchHostWithPattern(host, pattern));
}

export function matchAnyHost(
  hosts: (string | undefined)[],
  patterns: string[],
): boolean {
  return Array.from(
    new Set(
      hosts.filter(
        (host): host is Exclude<typeof host, undefined> => host !== undefined,
      ),
    ),
  ).some(host => patterns.some(pattern => matchHostWithPattern(host, pattern)));
}

function matchHostWithPattern(host: string, pattern: string): boolean {
  if (minimatch(host, pattern)) {
    return true;
  }

  if (pattern.startsWith('*.') && minimatch(host, pattern.slice(2))) {
    return true;
  }

  return false;
}
