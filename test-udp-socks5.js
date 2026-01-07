#!/usr/bin/env node
/**
 * Test SOCKS5 UDP ASSOCIATE functionality by sending DNS queries.
 *
 * Usage:
 *   node test-udp-socks5.js [proxy_host] [proxy_port] [dns_server] [domain]
 *
 * Example:
 *   node test-udp-socks5.js 127.0.0.1 1080 8.8.8.8 google.com
 */

const net = require('net');
const dgram = require('dgram');

/**
 * Perform SOCKS5 UDP ASSOCIATE handshake
 */
async function socks5UdpAssociate(proxyHost, proxyPort) {
  return new Promise((resolve, reject) => {
    const tcpSocket = net.connect(proxyPort, proxyHost);

    tcpSocket.on('error', reject);

    let step = 0;

    tcpSocket.on('connect', () => {
      console.log('✅ Connected to SOCKS5 proxy');

      // Send SOCKS5 greeting (no authentication)
      // VER(1) NMETHODS(1) METHODS(1)
      tcpSocket.write(Buffer.from([0x05, 0x01, 0x00]));
    });

    tcpSocket.on('data', (data) => {
      if (step === 0) {
        // Authentication response
        if (data.length >= 2 && data[0] === 0x05 && data[1] === 0x00) {
          console.log('✅ SOCKS5 authentication successful');
          step = 1;

          // Send UDP ASSOCIATE request
          // VER(1) CMD(3) RSV(0) ATYP(1) DST.ADDR(4) DST.PORT(2)
          const request = Buffer.alloc(10);
          request[0] = 0x05;  // VER
          request[1] = 0x03;  // CMD: UDP ASSOCIATE
          request[2] = 0x00;  // RSV
          request[3] = 0x01;  // ATYP: IPv4
          // DST.ADDR: 0.0.0.0 (4 bytes, already zeros)
          // DST.PORT: 0 (2 bytes, already zeros)

          tcpSocket.write(request);
        } else {
          reject(new Error(`Authentication failed: ${data.toString('hex')}`));
        }
      } else if (step === 1) {
        // UDP ASSOCIATE response
        if (data.length >= 10) {
          const ver = data[0];
          const rep = data[1];
          const atyp = data[3];

          if (rep !== 0) {
            reject(new Error(`UDP ASSOCIATE failed with code: ${rep}`));
            return;
          }

          let relayAddr, relayPort;

          if (atyp === 0x01) {
            // IPv4
            relayAddr = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
            relayPort = data.readUInt16BE(8);
          } else if (atyp === 0x04) {
            // IPv6
            const parts = [];
            for (let i = 0; i < 8; i++) {
              parts.push(data.readUInt16BE(4 + i * 2).toString(16));
            }
            relayAddr = parts.join(':');
            relayPort = data.readUInt16BE(20);
          } else {
            reject(new Error(`Unsupported address type: ${atyp}`));
            return;
          }

          console.log('✅ UDP ASSOCIATE successful');
          console.log(`   Relay address: ${relayAddr}:${relayPort}`);

          resolve({
            tcpSocket,
            relayAddr,
            relayPort
          });
        } else {
          reject(new Error('Invalid UDP ASSOCIATE response'));
        }
      }
    });
  });
}

/**
 * Build SOCKS5 UDP packet format
 */
function buildSocks5UdpPacket(destAddr, destPort, data) {
  const parts = destAddr.split('.');
  const isIPv4 = parts.length === 4 && parts.every(p => !isNaN(parseInt(p)));

  let packet;

  if (isIPv4) {
    // IPv4
    packet = Buffer.allocUnsafe(10 + data.length);
    packet.writeUInt16BE(0x0000, 0);  // RSV
    packet[2] = 0x00;                  // FRAG
    packet[3] = 0x01;                  // ATYP: IPv4

    // Write IPv4 address
    parts.forEach((octet, i) => {
      packet[4 + i] = parseInt(octet);
    });

    packet.writeUInt16BE(destPort, 8);
    data.copy(packet, 10);
  } else {
    // Assume domain (ATYP = 0x03)
    const domainBuf = Buffer.from(destAddr, 'ascii');
    packet = Buffer.allocUnsafe(7 + domainBuf.length + data.length);
    packet.writeUInt16BE(0x0000, 0);  // RSV
    packet[2] = 0x00;                  // FRAG
    packet[3] = 0x03;                  // ATYP: Domain
    packet[4] = domainBuf.length;      // Domain length
    domainBuf.copy(packet, 5);
    packet.writeUInt16BE(destPort, 5 + domainBuf.length);
    data.copy(packet, 7 + domainBuf.length);
  }

  return packet;
}

/**
 * Parse SOCKS5 UDP response packet
 */
function parseSocks5UdpResponse(data) {
  if (data.length < 10) {
    throw new Error('Response too short');
  }

  const rsv = data.readUInt16BE(0);
  const frag = data[2];
  const atyp = data[3];

  let addr, port, payload;

  if (atyp === 0x01) {
    // IPv4
    addr = `${data[4]}.${data[5]}.${data[6]}.${data[7]}`;
    port = data.readUInt16BE(8);
    payload = data.slice(10);
  } else if (atyp === 0x04) {
    // IPv6
    const parts = [];
    for (let i = 0; i < 8; i++) {
      parts.push(data.readUInt16BE(4 + i * 2).toString(16));
    }
    addr = parts.join(':');
    port = data.readUInt16BE(20);
    payload = data.slice(22);
  } else if (atyp === 0x03) {
    // Domain
    const len = data[4];
    addr = data.slice(5, 5 + len).toString('ascii');
    port = data.readUInt16BE(5 + len);
    payload = data.slice(7 + len);
  } else {
    throw new Error(`Unsupported address type: ${atyp}`);
  }

  return { addr, port, payload };
}

/**
 * Build a simple DNS A record query
 */
function buildDnsQuery(domain) {
  const parts = [];

  // Transaction ID (random)
  const txid = Math.floor(Math.random() * 65536);
  parts.push(Buffer.from([txid >> 8, txid & 0xff]));

  // Flags: standard query (0x0100)
  parts.push(Buffer.from([0x01, 0x00]));

  // Questions: 1, Answers: 0, Authority: 0, Additional: 0
  parts.push(Buffer.from([0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]));

  // Question section
  const labels = domain.split('.');
  for (const label of labels) {
    parts.push(Buffer.from([label.length]));
    parts.push(Buffer.from(label, 'ascii'));
  }
  parts.push(Buffer.from([0x00]));  // End of name

  // Type A (1), Class IN (1)
  parts.push(Buffer.from([0x00, 0x01, 0x00, 0x01]));

  return Buffer.concat(parts);
}

/**
 * Parse DNS response to extract IP addresses
 */
function parseDnsResponse(data) {
  if (data.length < 12) {
    return { valid: false, error: 'Response too short' };
  }

  const txid = data.readUInt16BE(0);
  const flags = data.readUInt16BE(2);
  const isResponse = (flags & 0x8000) !== 0;
  const rcode = flags & 0x000f;

  if (!isResponse) {
    return { valid: false, error: 'Not a response' };
  }

  if (rcode !== 0) {
    return { valid: false, error: `DNS error code: ${rcode}` };
  }

  const questions = data.readUInt16BE(4);
  const answers = data.readUInt16BE(6);

  return {
    valid: true,
    txid,
    questions,
    answers,
    rcode
  };
}

/**
 * Test SOCKS5 UDP by sending a DNS query
 */
async function testDnsQuery(proxyHost, proxyPort, dnsServer, domain) {
  console.log('\n🧪 Testing SOCKS5 UDP ASSOCIATE');
  console.log(`   Proxy: ${proxyHost}:${proxyPort}`);
  console.log(`   DNS Server: ${dnsServer}`);
  console.log(`   Query: ${domain}`);
  console.log();

  let tcpSocket, udpSocket;

  try {
    // Establish UDP ASSOCIATE
    const { tcpSocket: tcp, relayAddr, relayPort } = await socks5UdpAssociate(proxyHost, proxyPort);
    tcpSocket = tcp;

    // Create UDP socket
    udpSocket = dgram.createSocket('udp4');

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        cleanup();
        reject(new Error('Timeout waiting for DNS response'));
      }, 5000);

      const cleanup = () => {
        clearTimeout(timeout);
        if (udpSocket) udpSocket.close();
        if (tcpSocket) tcpSocket.end();
      };

      udpSocket.on('error', (err) => {
        cleanup();
        reject(err);
      });

      udpSocket.on('message', (msg, rinfo) => {
        try {
          console.log(`📥 Received ${msg.length} bytes from ${rinfo.address}:${rinfo.port}`);

          // Parse SOCKS5 UDP response
          const { addr, port, payload } = parseSocks5UdpResponse(msg);
          console.log(`✅ Response from DNS server: ${addr}:${port}`);
          console.log(`   DNS response payload: ${payload.length} bytes`);

          // Parse DNS response
          const dnsResult = parseDnsResponse(payload);

          if (dnsResult.valid) {
            console.log('✅ Valid DNS response received!');
            console.log(`   Transaction ID: 0x${dnsResult.txid.toString(16).padStart(4, '0')}`);
            console.log(`   Questions: ${dnsResult.questions}, Answers: ${dnsResult.answers}`);
            cleanup();
            resolve(true);
          } else {
            console.log(`⚠️  DNS response invalid: ${dnsResult.error}`);
            cleanup();
            resolve(false);
          }
        } catch (err) {
          cleanup();
          reject(err);
        }
      });

      // Build and send DNS query
      const dnsQuery = buildDnsQuery(domain);
      console.log(`📤 Sending DNS query (${dnsQuery.length} bytes)`);

      // Wrap in SOCKS5 UDP packet
      const socks5Packet = buildSocks5UdpPacket(dnsServer, 53, dnsQuery);

      // Send to relay
      udpSocket.send(socks5Packet, relayPort, relayAddr, (err) => {
        if (err) {
          cleanup();
          reject(err);
        } else {
          console.log(`   Sent to relay ${relayAddr}:${relayPort}`);
          console.log('📥 Waiting for response...');
        }
      });
    });

  } catch (err) {
    if (tcpSocket) tcpSocket.end();
    if (udpSocket) udpSocket.close();
    throw err;
  }
}

// Main
async function main() {
  const proxyHost = process.argv[2] || '127.0.0.1';
  const proxyPort = parseInt(process.argv[3] || '1080');
  const dnsServer = process.argv[4] || '8.8.8.8';
  const domain = process.argv[5] || 'google.com';

  try {
    const success = await testDnsQuery(proxyHost, proxyPort, dnsServer, domain);

    if (success) {
      console.log('\n🎉 SOCKS5 UDP test PASSED!');
      process.exit(0);
    } else {
      console.log('\n❌ SOCKS5 UDP test FAILED!');
      process.exit(1);
    }
  } catch (err) {
    console.error('\n❌ Error:', err.message);
    if (err.stack) {
      console.error(err.stack);
    }
    process.exit(1);
  }
}

main();
