/**
 * PCAP File Parser
 * Reads binary .pcap files and extracts individual packets.
 *
 * PCAP Format:
 *   Global Header (24 bytes) — file metadata
 *   [Packet Header (16 bytes) + Packet Data (variable)] × N
 */

const fs = require('fs');

// Magic numbers to detect byte order
const PCAP_MAGIC_NATIVE = 0xa1b2c3d4;   // Native byte order
const PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;  // Swapped byte order

/**
 * Parse the 24-byte PCAP global header
 */
function parseGlobalHeader(buffer) {
  if (buffer.length < 24) {
    throw new Error('File too small to contain PCAP global header');
  }

  const magic = buffer.readUInt32LE(0);
  let needsSwap = false;

  if (magic === PCAP_MAGIC_NATIVE) {
    needsSwap = false;
  } else if (magic === PCAP_MAGIC_SWAPPED) {
    needsSwap = true;
  } else {
    throw new Error(`Invalid PCAP magic number: 0x${magic.toString(16)}`);
  }

  const read16 = needsSwap
    ? (buf, off) => buf.readUInt16BE(off)
    : (buf, off) => buf.readUInt16LE(off);
  const read32 = needsSwap
    ? (buf, off) => buf.readUInt32BE(off)
    : (buf, off) => buf.readUInt32LE(off);

  return {
    magic,
    versionMajor: read16(buffer, 4),
    versionMinor: read16(buffer, 6),
    thisZone: read32(buffer, 8),
    sigFigs: read32(buffer, 12),
    snapLen: read32(buffer, 16),
    network: read32(buffer, 20),   // 1 = Ethernet
    needsSwap,
    read16,
    read32,
  };
}

/**
 * Parse a single 16-byte packet header
 */
function parsePacketHeader(buffer, offset, read32) {
  if (offset + 16 > buffer.length) {
    return null; // End of file
  }

  return {
    tsSec: read32(buffer, offset),
    tsUsec: read32(buffer, offset + 4),
    inclLen: read32(buffer, offset + 8),  // Bytes saved in file
    origLen: read32(buffer, offset + 12), // Original packet size
  };
}

/**
 * Parse an entire PCAP file and return all packets
 * @param {string} filePath - Path to the .pcap file
 * @returns {{ globalHeader: object, packets: Array<{ header: object, data: Buffer }> }}
 */
function parsePcapFile(filePath) {
  const fileBuffer = fs.readFileSync(filePath);

  // Parse global header
  const globalHeader = parseGlobalHeader(fileBuffer);
  const { read32, snapLen } = globalHeader;

  const packets = [];
  let offset = 24; // Start after global header

  while (offset < fileBuffer.length) {
    // Parse packet header
    const pktHeader = parsePacketHeader(fileBuffer, offset, read32);
    if (!pktHeader) break;

    offset += 16;

    // Validate packet length
    if (pktHeader.inclLen > snapLen || pktHeader.inclLen > 65535) {
      console.warn(`Invalid packet length: ${pktHeader.inclLen} at offset ${offset - 16}`);
      break;
    }

    if (offset + pktHeader.inclLen > fileBuffer.length) {
      console.warn('Truncated packet at end of file');
      break;
    }

    // Extract packet data
    const data = fileBuffer.slice(offset, offset + pktHeader.inclLen);
    offset += pktHeader.inclLen;

    packets.push({
      header: pktHeader,
      data,
    });
  }

  return {
    globalHeader: {
      version: `${globalHeader.versionMajor}.${globalHeader.versionMinor}`,
      snapLen: globalHeader.snapLen,
      linkType: globalHeader.network,
      linkTypeName: globalHeader.network === 1 ? 'Ethernet' : `Unknown(${globalHeader.network})`,
    },
    packets,
  };
}

/**
 * Write packets back to a PCAP file (for filtered export)
 * @param {string} filePath - Output file path
 * @param {Array<{ header: object, data: Buffer }>} packets - Packets to write
 */
function writePcapFile(filePath, packets) {
  const chunks = [];

  // Write global header (native byte order)
  const globalHeader = Buffer.alloc(24);
  globalHeader.writeUInt32LE(PCAP_MAGIC_NATIVE, 0);
  globalHeader.writeUInt16LE(2, 4);      // Version major
  globalHeader.writeUInt16LE(4, 6);      // Version minor
  globalHeader.writeInt32LE(0, 8);       // Timezone
  globalHeader.writeUInt32LE(0, 12);     // Sigfigs
  globalHeader.writeUInt32LE(65535, 16); // Snaplen
  globalHeader.writeUInt32LE(1, 20);     // Ethernet
  chunks.push(globalHeader);

  // Write each packet
  for (const pkt of packets) {
    const pktHeader = Buffer.alloc(16);
    pktHeader.writeUInt32LE(pkt.header.tsSec, 0);
    pktHeader.writeUInt32LE(pkt.header.tsUsec, 4);
    pktHeader.writeUInt32LE(pkt.data.length, 8);
    pktHeader.writeUInt32LE(pkt.data.length, 12);
    chunks.push(pktHeader);
    chunks.push(pkt.data);
  }

  fs.writeFileSync(filePath, Buffer.concat(chunks));
}

module.exports = {
  parsePcapFile,
  writePcapFile,
  parseGlobalHeader,
};
