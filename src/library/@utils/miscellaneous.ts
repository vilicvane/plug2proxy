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

export function matchHost(host: string, pattern: string): boolean {
  if (minimatch(host, pattern)) {
    return true;
  }

  if (pattern.startsWith('*.') && minimatch(host, pattern.slice(2))) {
    return true;
  }

  return false;
}
