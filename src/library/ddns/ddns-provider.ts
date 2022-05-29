export interface IDDNSProvider {
  readonly name: string;

  update(ip: string): Promise<void>;
}
