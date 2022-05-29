export interface IDDNSProvider {
  update(ip: string): Promise<void>;
}
