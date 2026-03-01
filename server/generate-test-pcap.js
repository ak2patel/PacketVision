/**
 * PacketVision — Test PCAP Generator
 *
 * Generates a sample .pcap file with diverse packet types for testing:
 *  - TLS Client Hello with SNI (Google, YouTube, Facebook, Netflix, etc.)
 *  - HTTP GET requests with Host headers
 *  - DNS queries
 *  - Plain TCP/UDP packets
 *
 * Usage:
 *   node generate-test-pcap.js
 *   → Creates "test_packetvision.pcap" in the current directory
 */

const fs = require('fs');
const path = require('path');

const OUTPUT = path.join(__dirname, 'test_packetvision.pcap');

// ─── Helpers ───

function u8(val) { const b = Buffer.alloc(1); b.writeUInt8(val); return b; }
function u16BE(val) { const b = Buffer.alloc(2); b.writeUInt16BE(val); return b; }
function u32BE(val) { const b = Buffer.alloc(4); b.writeUInt32BE(val); return b; }
function u16LE(val) { const b = Buffer.alloc(2); b.writeUInt16LE(val); return b; }
function u32LE(val) { const b = Buffer.alloc(4); b.writeUInt32LE(val); return b; }

function macBytes(mac) {
  return Buffer.from(mac.split(':').map(h => parseInt(h, 16)));
}

function ipBytes(ip) {
  return Buffer.from(ip.split('.').map(n => parseInt(n)));
}

function randomBytes(len) {
  const buf = Buffer.alloc(len);
  for (let i = 0; i < len; i++) buf[i] = Math.floor(Math.random() * 256);
  return buf;
}

// ─── Packet Builders ───

function buildEthernet(srcMac, dstMac, etherType) {
  return Buffer.concat([macBytes(dstMac), macBytes(srcMac), u16BE(etherType)]);
}

function buildIPv4(srcIp, dstIp, protocol, payload) {
  const totalLen = 20 + payload.length;
  const header = Buffer.concat([
    u8(0x45),           // Version + IHL
    u8(0x00),           // DSCP
    u16BE(totalLen),    // Total length
    u16BE(0x1234),      // ID
    u16BE(0x4000),      // Flags + Fragment
    u8(64),             // TTL
    u8(protocol),       // Protocol
    u16BE(0x0000),      // Checksum (skip)
    ipBytes(srcIp),
    ipBytes(dstIp),
  ]);
  return Buffer.concat([header, payload]);
}

function buildTCP(srcPort, dstPort, payload, flags = 0x18) {
  const dataOffset = 5;
  const header = Buffer.concat([
    u16BE(srcPort),
    u16BE(dstPort),
    u32BE(1000),                    // Seq
    u32BE(0),                       // Ack
    u8((dataOffset << 4) | 0x00),   // Data offset
    u8(flags),                      // Flags (PSH+ACK)
    u16BE(65535),                   // Window
    u16BE(0x0000),                  // Checksum
    u16BE(0x0000),                  // Urgent
  ]);
  return Buffer.concat([header, payload]);
}

function buildUDP(srcPort, dstPort, payload) {
  const length = 8 + payload.length;
  const header = Buffer.concat([
    u16BE(srcPort),
    u16BE(dstPort),
    u16BE(length),
    u16BE(0x0000),    // Checksum
  ]);
  return Buffer.concat([header, payload]);
}

// ─── TLS Client Hello with SNI ───

function buildTLSClientHello(sni) {
  // SNI extension
  const sniBytes = Buffer.from(sni, 'ascii');
  const sniExtension = Buffer.concat([
    u16BE(0x0000),                          // Extension type: SNI
    u16BE(sniBytes.length + 5),             // Extension length
    u16BE(sniBytes.length + 3),             // SNI list length
    u8(0x00),                               // SNI type: hostname
    u16BE(sniBytes.length),                 // Hostname length
    sniBytes,
  ]);

  // Other extensions (supported versions, key share — minimal)
  const otherExtension = Buffer.concat([
    u16BE(0x002b),        // Supported versions
    u16BE(3),
    u8(2),
    u16BE(0x0303),        // TLS 1.2
  ]);

  const extensions = Buffer.concat([sniExtension, otherExtension]);

  // Client Hello body
  const clientRandom = randomBytes(32);
  const sessionId = randomBytes(32);
  const cipherSuites = Buffer.concat([
    u16BE(4),             // 2 cipher suites
    u16BE(0x1301),        // TLS_AES_128_GCM_SHA256
    u16BE(0xc02f),        // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  ]);
  const compression = Buffer.concat([u8(1), u8(0x00)]);

  const helloBody = Buffer.concat([
    u16BE(0x0303),          // Client version: TLS 1.2
    clientRandom,
    u8(sessionId.length),
    sessionId,
    cipherSuites,
    compression,
    u16BE(extensions.length),
    extensions,
  ]);

  // Handshake header
  const handshakeLen = helloBody.length;
  const handshake = Buffer.concat([
    u8(0x01),                                   // Handshake type: Client Hello
    u8((handshakeLen >> 16) & 0xff),
    u8((handshakeLen >> 8) & 0xff),
    u8(handshakeLen & 0xff),
    helloBody,
  ]);

  // TLS record
  const record = Buffer.concat([
    u8(0x16),               // Content type: Handshake
    u16BE(0x0301),          // Version: TLS 1.0 (compat)
    u16BE(handshake.length),
    handshake,
  ]);

  return record;
}

// ─── HTTP Request ───

function buildHTTPRequest(host, path_url = '/') {
  const request = `GET ${path_url} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: PacketVision-Test/1.0\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n`;
  return Buffer.from(request, 'ascii');
}

// ─── DNS Query ───

function buildDNSQuery(domain) {
  const labels = domain.split('.');
  const qname = Buffer.concat([
    ...labels.map(l => Buffer.concat([u8(l.length), Buffer.from(l, 'ascii')])),
    u8(0),
  ]);

  return Buffer.concat([
    u16BE(0xabcd),    // Transaction ID
    u16BE(0x0100),    // Flags: standard query
    u16BE(1),         // Questions
    u16BE(0),         // Answers
    u16BE(0),         // Authority
    u16BE(0),         // Additional
    qname,
    u16BE(1),         // Type: A
    u16BE(1),         // Class: IN
  ]);
}

// ─── Assemble full packet ───

function makePacket(srcMac, dstMac, srcIp, dstIp, protocol, transportPayload, tsSec) {
  const ethHeader = buildEthernet(srcMac, dstMac, 0x0800);
  const ipPayload = buildIPv4(srcIp, dstIp, protocol, transportPayload);
  const fullPacket = Buffer.concat([ethHeader, ipPayload]);

  // PCAP packet header (16 bytes, little-endian)
  const inclLen = fullPacket.length;
  const pktHeader = Buffer.concat([
    u32LE(tsSec),     // ts_sec
    u32LE(0),         // ts_usec
    u32LE(inclLen),   // incl_len
    u32LE(inclLen),   // orig_len
  ]);

  return Buffer.concat([pktHeader, fullPacket]);
}

// ═══════════════════════════════════════
// Generate the test PCAP
// ═══════════════════════════════════════

console.log('🔧 Generating test PCAP file...\n');

const chunks = [];
let packetCount = 0;
const baseSec = Math.floor(Date.now() / 1000);

// PCAP Global Header
const globalHeader = Buffer.concat([
  u32LE(0xa1b2c3d4),   // Magic
  u16LE(2), u16LE(4),  // Version 2.4
  u32LE(0),             // Timezone
  u32LE(0),             // Sigfigs
  u32LE(65535),         // Snaplen
  u32LE(1),             // Ethernet
]);
chunks.push(globalHeader);

const CLIENT_MAC = 'aa:bb:cc:dd:ee:01';
const SERVER_MAC = 'aa:bb:cc:dd:ee:02';
const CLIENT_IP = '192.168.1.100';

// ─── TLS Client Hellos (HTTPS) ───
const tlsSites = [
  { domain: 'www.google.com',      ip: '142.250.190.78' },
  { domain: 'www.youtube.com',     ip: '142.250.80.46' },
  { domain: 'www.facebook.com',    ip: '157.240.1.35' },
  { domain: 'www.instagram.com',   ip: '157.240.229.174' },
  { domain: 'twitter.com',         ip: '104.244.42.193' },
  { domain: 'www.amazon.com',      ip: '54.239.28.85' },
  { domain: 'www.netflix.com',     ip: '54.74.73.31' },
  { domain: 'github.com',          ip: '140.82.121.3' },
  { domain: 'discord.com',         ip: '162.159.135.232' },
  { domain: 'zoom.us',             ip: '170.114.52.2' },
  { domain: 'web.telegram.org',    ip: '149.154.167.99' },
  { domain: 'www.tiktok.com',      ip: '104.18.36.115' },
  { domain: 'open.spotify.com',    ip: '35.186.224.25' },
  { domain: 'www.cloudflare.com',  ip: '104.16.123.96' },
  { domain: 'www.microsoft.com',   ip: '20.70.246.20' },
  { domain: 'www.apple.com',       ip: '17.253.144.10' },
  { domain: 'www.whatsapp.com',    ip: '157.240.9.52' },
  { domain: 'www.linkedin.com',    ip: '13.107.42.14' },
  { domain: 'www.reddit.com',      ip: '151.101.1.140' },
  { domain: 'stackoverflow.com',   ip: '151.101.1.69' },
];

tlsSites.forEach((site, i) => {
  const tls = buildTLSClientHello(site.domain);
  const tcp = buildTCP(40000 + i, 443, tls);
  chunks.push(makePacket(CLIENT_MAC, SERVER_MAC, CLIENT_IP, site.ip, 6, tcp, baseSec + i));
  packetCount++;

  // Add a SYN packet before each (looks more realistic)
  const syn = buildTCP(40000 + i, 443, Buffer.alloc(0), 0x02);
  chunks.push(makePacket(CLIENT_MAC, SERVER_MAC, CLIENT_IP, site.ip, 6, syn, baseSec + i));
  packetCount++;

  // Add a response ACK
  const ack = buildTCP(443, 40000 + i, Buffer.alloc(0), 0x10);
  chunks.push(makePacket(SERVER_MAC, CLIENT_MAC, site.ip, CLIENT_IP, 6, ack, baseSec + i));
  packetCount++;
});

// ─── HTTP Requests ───
const httpSites = [
  { host: 'example.com',    ip: '93.184.216.34',  path: '/' },
  { host: 'httpbin.org',    ip: '34.227.213.82',  path: '/get' },
  { host: 'api.myapp.com',  ip: '10.0.0.5',       path: '/api/v1/users' },
  { host: 'blog.site.com',  ip: '10.0.0.6',       path: '/posts' },
];

httpSites.forEach((site, i) => {
  const http = buildHTTPRequest(site.host, site.path);
  const tcp = buildTCP(50000 + i, 80, http);
  chunks.push(makePacket(CLIENT_MAC, SERVER_MAC, CLIENT_IP, site.ip, 6, tcp, baseSec + 25 + i));
  packetCount++;
});

// ─── DNS Queries ───
const dnsQueries = [
  'www.google.com', 'api.twitter.com', 'cdn.netflix.com',
  'static.github.com', 'media.discord.com',
];

dnsQueries.forEach((domain, i) => {
  const dns = buildDNSQuery(domain);
  const udp = buildUDP(12345 + i, 53, dns);
  chunks.push(makePacket(CLIENT_MAC, SERVER_MAC, CLIENT_IP, '8.8.8.8', 17, udp, baseSec + 30 + i));
  packetCount++;
});

// ─── Plain TCP traffic (Unknown apps) ───
for (let i = 0; i < 10; i++) {
  const payload = randomBytes(Math.floor(Math.random() * 200) + 50);
  const tcp = buildTCP(60000 + i, 8080 + i, payload);
  chunks.push(makePacket(CLIENT_MAC, SERVER_MAC, CLIENT_IP, `10.0.${i}.1`, 6, tcp, baseSec + 40 + i));
  packetCount++;
}

// ─── Write file ───
const pcapData = Buffer.concat(chunks);
fs.writeFileSync(OUTPUT, pcapData);

console.log(`✅ Generated: ${OUTPUT}`);
console.log(`📦 Total packets: ${packetCount}`);
console.log(`📏 File size: ${(pcapData.length / 1024).toFixed(1)} KB`);
console.log(`\n📊 Breakdown:`);
console.log(`   TLS Client Hellos:  ${tlsSites.length} (+ ${tlsSites.length * 2} SYN/ACK)`);
console.log(`   HTTP Requests:      ${httpSites.length}`);
console.log(`   DNS Queries:        ${dnsQueries.length}`);
console.log(`   Plain TCP:          10`);
console.log(`\n🚀 Upload this file to PacketVision at http://localhost:5173 to test!`);
