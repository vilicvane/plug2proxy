export function groupRawHeaders(rawHeaders: string[]): [string, string][] {
  let headers: [string, string][] = [];

  for (let i = 0; i < rawHeaders.length; i += 2) {
    headers.push([rawHeaders[i], rawHeaders[i + 1]]);
  }

  return headers;
}
