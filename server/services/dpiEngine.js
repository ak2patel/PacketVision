/**
 * DPI Engine — Deep Packet Inspection
 *
 * Extracts application-layer identifiers from packet payloads:
 * 1. TLS Client Hello → SNI (Server Name Indication)
 * 2. HTTP Request → Host header
 * 3. DNS Query → Domain name
 *
 * Then classifies traffic into known applications.
 */

const { PROTOCOL } = require('./packetParser');

// ─── Application types ───
const APP_TYPES = {
  UNKNOWN: 'Unknown',
  HTTP: 'HTTP',
  HTTPS: 'HTTPS',
  DNS: 'DNS',
  GOOGLE: 'Google',
  YOUTUBE: 'YouTube',
  FACEBOOK: 'Facebook',
  INSTAGRAM: 'Instagram',
  TWITTER: 'Twitter/X',
  AMAZON: 'Amazon',
  NETFLIX: 'Netflix',
  GITHUB: 'GitHub',
  DISCORD: 'Discord',
  ZOOM: 'Zoom',
  TELEGRAM: 'Telegram',
  TIKTOK: 'TikTok',
  SPOTIFY: 'Spotify',
  CLOUDFLARE: 'Cloudflare',
  MICROSOFT: 'Microsoft',
  APPLE: 'Apple',
  WHATSAPP: 'WhatsApp',
  LINKEDIN: 'LinkedIn',
  REDDIT: 'Reddit',
  STACKOVERFLOW: 'StackOverflow',
};

// ─── Domain → App mapping ───
const DOMAIN_PATTERNS = [
  { pattern: 'youtube',       app: APP_TYPES.YOUTUBE },
  { pattern: 'googlevideo',   app: APP_TYPES.YOUTUBE },
  { pattern: 'ytimg',         app: APP_TYPES.YOUTUBE },
  { pattern: 'facebook',      app: APP_TYPES.FACEBOOK },
  { pattern: 'fbcdn',         app: APP_TYPES.FACEBOOK },
  { pattern: 'instagram',     app: APP_TYPES.INSTAGRAM },
  { pattern: 'cdninstagram',  app: APP_TYPES.INSTAGRAM },
  { pattern: 'netflix',       app: APP_TYPES.NETFLIX },
  { pattern: 'nflxvideo',     app: APP_TYPES.NETFLIX },
  { pattern: 'twitter',       app: APP_TYPES.TWITTER },
  { pattern: 'twimg',         app: APP_TYPES.TWITTER },
  { pattern: 'amazon',        app: APP_TYPES.AMAZON },
  { pattern: 'amazonaws',     app: APP_TYPES.AMAZON },
  { pattern: 'github',        app: APP_TYPES.GITHUB },
  { pattern: 'githubusercontent', app: APP_TYPES.GITHUB },
  { pattern: 'discord',       app: APP_TYPES.DISCORD },
  { pattern: 'discordapp',    app: APP_TYPES.DISCORD },
  { pattern: 'zoom',          app: APP_TYPES.ZOOM },
  { pattern: 'telegram',      app: APP_TYPES.TELEGRAM },
  { pattern: 'tiktok',        app: APP_TYPES.TIKTOK },
  { pattern: 'tiktokcdn',     app: APP_TYPES.TIKTOK },
  { pattern: 'spotify',       app: APP_TYPES.SPOTIFY },
  { pattern: 'scdn',          app: APP_TYPES.SPOTIFY },
  { pattern: 'cloudflare',    app: APP_TYPES.CLOUDFLARE },
  { pattern: 'microsoft',     app: APP_TYPES.MICROSOFT },
  { pattern: 'windows',       app: APP_TYPES.MICROSOFT },
  { pattern: 'live.com',      app: APP_TYPES.MICROSOFT },
  { pattern: 'apple',         app: APP_TYPES.APPLE },
  { pattern: 'icloud',        app: APP_TYPES.APPLE },
  { pattern: 'whatsapp',      app: APP_TYPES.WHATSAPP },
  { pattern: 'linkedin',      app: APP_TYPES.LINKEDIN },
  { pattern: 'reddit',        app: APP_TYPES.REDDIT },
  { pattern: 'redd.it',       app: APP_TYPES.REDDIT },
  { pattern: 'stackoverflow', app: APP_TYPES.STACKOVERFLOW },
  { pattern: 'google',        app: APP_TYPES.GOOGLE },
  { pattern: 'gstatic',       app: APP_TYPES.GOOGLE },
  { pattern: 'googleapis',    app: APP_TYPES.GOOGLE },
];

// ─── TLS Constants ───
const TLS_CONTENT_HANDSHAKE = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO = 0x01;
const TLS_EXTENSION_SNI = 0x0000;
const TLS_SNI_TYPE_HOSTNAME = 0x00;

/**
 * Read a 16-bit big-endian value
 */
function readUint16BE(buf, offset) {
  return (buf[offset] << 8) | buf[offset + 1];
}

/**
 * Read a 24-bit big-endian value
 */
function readUint24BE(buf, offset) {
  return (buf[offset] << 16) | (buf[offset + 1] << 8) | buf[offset + 2];
}

// ═══════════════════════════════════════════════════
// TLS SNI Extraction
// ═══════════════════════════════════════════════════

/**
 * Check if payload is a TLS Client Hello
 */
function isTLSClientHello(payload, offset, length) {
  if (length < 9) return false;

  // Content Type = 0x16 (Handshake)
  if (payload[offset] !== TLS_CONTENT_HANDSHAKE) return false;

  // Version check (0x0300 to 0x0304)
  const version = readUint16BE(payload, offset + 1);
  if (version < 0x0300 || version > 0x0304) return false;

  // Record length sanity check
  const recordLen = readUint16BE(payload, offset + 3);
  if (recordLen > length - 5) return false;

  // Handshake Type = 0x01 (Client Hello)
  if (payload[offset + 5] !== TLS_HANDSHAKE_CLIENT_HELLO) return false;

  return true;
}

/**
 * Extract SNI from a TLS Client Hello payload
 * @param {Buffer} payload - Full packet data
 * @param {number} payloadOffset - Where the TLS data starts
 * @param {number} payloadLength - Length of the TLS data
 * @returns {string|null} The extracted hostname or null
 */
function extractSNI(payload, payloadOffset, payloadLength) {
  if (!isTLSClientHello(payload, payloadOffset, payloadLength)) {
    return null;
  }

  try {
    let offset = payloadOffset + 5; // Skip TLS record header

    // Skip handshake header (1 type + 3 length)
    offset += 4;

    // Skip client version (2)
    offset += 2;

    // Skip random (32)
    offset += 32;

    // Skip session ID
    if (offset >= payloadOffset + payloadLength) return null;
    const sessionIdLen = payload[offset];
    offset += 1 + sessionIdLen;

    // Skip cipher suites
    if (offset + 2 > payloadOffset + payloadLength) return null;
    const cipherSuitesLen = readUint16BE(payload, offset);
    offset += 2 + cipherSuitesLen;

    // Skip compression methods
    if (offset >= payloadOffset + payloadLength) return null;
    const compMethodsLen = payload[offset];
    offset += 1 + compMethodsLen;

    // Extensions length
    if (offset + 2 > payloadOffset + payloadLength) return null;
    const extensionsLen = readUint16BE(payload, offset);
    offset += 2;

    const extensionsEnd = Math.min(offset + extensionsLen, payloadOffset + payloadLength);

    // Search through extensions for SNI (type 0x0000)
    while (offset + 4 <= extensionsEnd) {
      const extType = readUint16BE(payload, offset);
      const extLen = readUint16BE(payload, offset + 2);
      offset += 4;

      if (offset + extLen > extensionsEnd) break;

      if (extType === TLS_EXTENSION_SNI) {
        // SNI extension found
        if (extLen < 5) break;

        const sniType = payload[offset + 2];
        if (sniType !== TLS_SNI_TYPE_HOSTNAME) break;

        const sniLen = readUint16BE(payload, offset + 3);
        if (sniLen > extLen - 5) break;

        return payload.toString('ascii', offset + 5, offset + 5 + sniLen);
      }

      offset += extLen;
    }
  } catch (e) {
    // Malformed packet — return null
  }

  return null;
}

// ═══════════════════════════════════════════════════
// HTTP Host Extraction
// ═══════════════════════════════════════════════════

/**
 * Check if payload starts with an HTTP method
 */
function isHTTPRequest(payload, offset, length) {
  if (length < 4) return false;

  const methods = ['GET ', 'POST', 'PUT ', 'HEAD', 'DELE', 'PATC', 'OPTI'];
  const start = payload.toString('ascii', offset, offset + 4);
  return methods.includes(start);
}

/**
 * Extract the Host header from an HTTP request
 * @param {Buffer} payload - Full packet data
 * @param {number} payloadOffset - Where HTTP data starts
 * @param {number} payloadLength - Length of HTTP data
 * @returns {string|null} The extracted hostname or null
 */
function extractHTTPHost(payload, payloadOffset, payloadLength) {
  if (!isHTTPRequest(payload, payloadOffset, payloadLength)) {
    return null;
  }

  try {
    const httpStr = payload.toString('ascii', payloadOffset, payloadOffset + Math.min(payloadLength, 2048));

    // Find "Host:" header (case-insensitive)
    const hostMatch = httpStr.match(/[Hh]ost:\s*([^\r\n]+)/);
    if (!hostMatch) return null;

    let host = hostMatch[1].trim();

    // Remove port if present
    const colonIdx = host.indexOf(':');
    if (colonIdx !== -1) {
      host = host.substring(0, colonIdx);
    }

    return host;
  } catch (e) {
    return null;
  }
}

// ═══════════════════════════════════════════════════
// DNS Query Extraction
// ═══════════════════════════════════════════════════

/**
 * Extract the queried domain name from a DNS packet
 */
function extractDNSQuery(payload, payloadOffset, payloadLength) {
  if (payloadLength < 12) return null;

  try {
    // Check QR bit (byte 2 of DNS header) — 0 = query
    const flags = payload[payloadOffset + 2];
    if (flags & 0x80) return null; // It's a response

    // Question count (bytes 4-5)
    const qdCount = readUint16BE(payload, payloadOffset + 4);
    if (qdCount === 0) return null;

    // Parse question domain (starts at byte 12)
    let offset = payloadOffset + 12;
    const labels = [];

    while (offset < payloadOffset + payloadLength) {
      const labelLen = payload[offset];
      if (labelLen === 0) break; // End of name
      if (labelLen > 63) break;  // Compression pointer, stop

      offset++;
      if (offset + labelLen > payloadOffset + payloadLength) break;

      labels.push(payload.toString('ascii', offset, offset + labelLen));
      offset += labelLen;
    }

    return labels.length > 0 ? labels.join('.') : null;
  } catch (e) {
    return null;
  }
}

// ═══════════════════════════════════════════════════
// App Classification
// ═══════════════════════════════════════════════════

/**
 * Map a domain/SNI to an application type
 * @param {string} domain - The extracted domain name
 * @returns {string} Application type from APP_TYPES
 */
function classifyDomain(domain) {
  if (!domain) return APP_TYPES.UNKNOWN;

  const lower = domain.toLowerCase();
  for (const { pattern, app } of DOMAIN_PATTERNS) {
    if (lower.includes(pattern)) {
      return app;
    }
  }

  return APP_TYPES.UNKNOWN;
}

/**
 * Inspect a parsed packet and extract DPI information
 * @param {Buffer} rawData - Raw packet bytes
 * @param {object} parsedPacket - Output from packetParser.parsePacket
 * @returns {object} DPI result { sni, appType, dnsQuery }
 */
function inspect(rawData, parsedPacket) {
  const { protocol, srcPort, destPort, payloadOffset, payloadLength } = parsedPacket;

  let sni = null;
  let appType = APP_TYPES.UNKNOWN;
  let dnsQuery = null;

  if (payloadLength <= 0) {
    // No payload — fallback to port-based classification
    if (destPort === 443) appType = APP_TYPES.HTTPS;
    else if (destPort === 80) appType = APP_TYPES.HTTP;
    else if (destPort === 53 || srcPort === 53) appType = APP_TYPES.DNS;
    return { sni, appType, dnsQuery };
  }

  // Try TLS SNI extraction (HTTPS, port 443)
  if (protocol === PROTOCOL.TCP && destPort === 443 && payloadLength > 5) {
    sni = extractSNI(rawData, payloadOffset, payloadLength);
    if (sni) {
      appType = classifyDomain(sni);
      if (appType === APP_TYPES.UNKNOWN) appType = APP_TYPES.HTTPS;
      return { sni, appType, dnsQuery };
    }
  }

  // Try HTTP Host extraction (port 80)
  if (protocol === PROTOCOL.TCP && destPort === 80 && payloadLength > 10) {
    sni = extractHTTPHost(rawData, payloadOffset, payloadLength);
    if (sni) {
      appType = classifyDomain(sni);
      if (appType === APP_TYPES.UNKNOWN) appType = APP_TYPES.HTTP;
      return { sni, appType, dnsQuery };
    }
  }

  // Try DNS query extraction (port 53)
  if (protocol === PROTOCOL.UDP && (destPort === 53 || srcPort === 53)) {
    dnsQuery = extractDNSQuery(rawData, payloadOffset, payloadLength);
    appType = APP_TYPES.DNS;
    return { sni: dnsQuery, appType, dnsQuery };
  }

  // Port-based fallback
  if (destPort === 443) appType = APP_TYPES.HTTPS;
  else if (destPort === 80) appType = APP_TYPES.HTTP;

  return { sni, appType, dnsQuery };
}

module.exports = {
  inspect,
  extractSNI,
  extractHTTPHost,
  extractDNSQuery,
  classifyDomain,
  APP_TYPES,
  DOMAIN_PATTERNS,
};
