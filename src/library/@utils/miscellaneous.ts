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
