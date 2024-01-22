export function getURLPort(url: URL): number {
  if (url.port) {
    return parseInt(url.port);
  }

  switch (url.protocol) {
    case 'http:':
      return 80;
    case 'https:':
      return 443;
    default:
      return -1;
  }
}
