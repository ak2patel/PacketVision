/**
 * Network Protocol Parser
 * Parses Ethernet, IPv4, TCP, and UDP headers from raw packet bytes.
 *
 * Packet structure (Ethernet + IPv4 + TCP):
 *   [Ethernet 14B][IPv4 20+B][TCP 20+B][Payload ...]
 */

// Protocol numbers
const PROTOCOL = {
  ICMP: 1,
  TCP: 6,
  UDP: 17,
};

// TCP Flag bitmasks
const TCP_FLAGS = {
  FIN: 0x01,
  SYN: 0x02,
  RST: 0x04,
  PSH: 0x08,
  ACK: 0x10,
  URG: 0x20,
};

/**
 * Parse a MAC address from 6 bytes into a string
 */
function parseMac(buffer, offset) {
  const bytes = [];
  for (let i = 0; i < 6; i++) {
    bytes.push(buffer.readUInt8(offset + i).toString(16).padStart(2, '0'));
  }
  return bytes.join(':');
}

/**
 * Parse an IPv4 address from 4 bytes into dotted string
 */
function parseIPv4(buffer, offset) {
  return `${buffer[offset]}.${buffer[offset + 1]}.${buffer[offset + 2]}.${buffer[offset + 3]}`;
}

/**
 * Decode TCP flags byte into human-readable string
 */
function decodeTcpFlags(flags) {
  const parts = [];
  if (flags & TCP_FLAGS.SYN) parts.push('SYN');
  if (flags & TCP_FLAGS.ACK) parts.push('ACK');
  if (flags & TCP_FLAGS.FIN) parts.push('FIN');
  if (flags & TCP_FLAGS.RST) parts.push('RST');
  if (flags & TCP_FLAGS.PSH) parts.push('PSH');
  if (flags & TCP_FLAGS.URG) parts.push('URG');
  return parts.length > 0 ? parts.join(' ') : 'none';
}

/**
 * Get protocol name from number
 */
function protocolName(num) {
  switch (num) {
    case PROTOCOL.ICMP: return 'ICMP';
    case PROTOCOL.TCP:  return 'TCP';
    case PROTOCOL.UDP:  return 'UDP';
    default: return `Unknown(${num})`;
  }
}

/**
 * Parse Ethernet header (14 bytes)
 *   Bytes 0-5:   Destination MAC
 *   Bytes 6-11:  Source MAC
 *   Bytes 12-13: EtherType (0x0800 = IPv4)
 */
function parseEthernet(data) {
  if (data.length < 14) return null;

  return {
    destMac: parseMac(data, 0),
    srcMac: parseMac(data, 6),
    etherType: data.readUInt16BE(12),
  };
}

/**
 * Parse IPv4 header (20+ bytes)
 *   Byte 0:      Version (4b) + IHL (4b)
 *   Byte 8:      TTL
 *   Byte 9:      Protocol
 *   Bytes 12-15: Source IP
 *   Bytes 16-19: Destination IP
 */
function parseIPv4Header(data, offset) {
  if (data.length < offset + 20) return null;

  const versionIhl = data.readUInt8(offset);
  const version = (versionIhl >> 4) & 0x0f;
  const ihl = versionIhl & 0x0f;
  const headerLen = ihl * 4;

  if (version !== 4) return null;
  if (data.length < offset + headerLen) return null;

  return {
    version,
    headerLen,
    ttl: data.readUInt8(offset + 8),
    protocol: data.readUInt8(offset + 9),
    protocolName: protocolName(data.readUInt8(offset + 9)),
    srcIp: parseIPv4(data, offset + 12),
    destIp: parseIPv4(data, offset + 16),
    totalLength: data.readUInt16BE(offset + 2),
  };
}

/**
 * Parse TCP header (20+ bytes)
 *   Bytes 0-1:   Source Port
 *   Bytes 2-3:   Destination Port
 *   Bytes 4-7:   Sequence Number
 *   Bytes 8-11:  Ack Number
 *   Byte 12:     Data Offset (upper 4 bits)
 *   Byte 13:     Flags
 */
function parseTCP(data, offset) {
  if (data.length < offset + 20) return null;

  const dataOffset = (data.readUInt8(offset + 12) >> 4) & 0x0f;
  const headerLen = dataOffset * 4;
  const flags = data.readUInt8(offset + 13);

  if (headerLen < 20 || data.length < offset + headerLen) return null;

  return {
    srcPort: data.readUInt16BE(offset),
    destPort: data.readUInt16BE(offset + 2),
    seqNumber: data.readUInt32BE(offset + 4),
    ackNumber: data.readUInt32BE(offset + 8),
    headerLen,
    flags,
    flagsStr: decodeTcpFlags(flags),
    window: data.readUInt16BE(offset + 14),
  };
}

/**
 * Parse UDP header (8 bytes)
 *   Bytes 0-1: Source Port
 *   Bytes 2-3: Destination Port
 *   Bytes 4-5: Length
 */
function parseUDP(data, offset) {
  if (data.length < offset + 8) return null;

  return {
    srcPort: data.readUInt16BE(offset),
    destPort: data.readUInt16BE(offset + 2),
    length: data.readUInt16BE(offset + 4),
    headerLen: 8,
  };
}

/**
 * Parse a complete packet from raw bytes
 * @param {Buffer} data - Raw packet bytes
 * @param {number} index - Packet index (for display)
 * @param {{ tsSec: number, tsUsec: number }} pktHeader - PCAP packet header
 * @returns {object|null} Parsed packet object or null if unparseable
 */
function parsePacket(data, index, pktHeader) {
  // Parse Ethernet
  const eth = parseEthernet(data);
  if (!eth) return null;

  // Only handle IPv4 (EtherType 0x0800)
  if (eth.etherType !== 0x0800) return null;

  // Parse IPv4
  let offset = 14; // After Ethernet header
  const ip = parseIPv4Header(data, offset);
  if (!ip) return null;

  offset += ip.headerLen;

  // Parse transport layer
  let transport = null;
  let srcPort = 0;
  let destPort = 0;
  let payloadOffset = offset;

  if (ip.protocol === PROTOCOL.TCP) {
    transport = parseTCP(data, offset);
    if (!transport) return null;
    srcPort = transport.srcPort;
    destPort = transport.destPort;
    payloadOffset = offset + transport.headerLen;
  } else if (ip.protocol === PROTOCOL.UDP) {
    transport = parseUDP(data, offset);
    if (!transport) return null;
    srcPort = transport.srcPort;
    destPort = transport.destPort;
    payloadOffset = offset + transport.headerLen;
  } else {
    // ICMP or other — skip transport parsing
    payloadOffset = offset;
  }

  // Calculate payload
  const payloadLength = Math.max(0, data.length - payloadOffset);

  // Build five-tuple string (for flow tracking)
  const fiveTuple = `${ip.srcIp}:${srcPort}-${ip.destIp}:${destPort}-${ip.protocol}`;

  return {
    index,
    timestamp: pktHeader
      ? new Date((pktHeader.tsSec * 1000) + Math.floor(pktHeader.tsUsec / 1000)).toISOString()
      : null,
    length: data.length,

    // Ethernet
    srcMac: eth.srcMac,
    destMac: eth.destMac,

    // IP
    srcIp: ip.srcIp,
    destIp: ip.destIp,
    protocol: ip.protocol,
    protocolName: ip.protocolName,
    ttl: ip.ttl,

    // Transport
    srcPort,
    destPort,
    tcpFlags: transport && ip.protocol === PROTOCOL.TCP ? transport.flagsStr : null,

    // Payload info
    payloadOffset,
    payloadLength,

    // Flow identifier
    fiveTuple,
  };
}

module.exports = {
  parsePacket,
  parseEthernet,
  parseIPv4Header,
  parseTCP,
  parseUDP,
  decodeTcpFlags,
  PROTOCOL,
  TCP_FLAGS,
};
