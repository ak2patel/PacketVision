/**
 * Analysis Service — Orchestrates the full DPI pipeline
 *
 * Flow: Upload → PCAP Parse → Packet Parse → DPI Inspect → Save to MongoDB
 *
 * Emits Socket.IO progress events during analysis.
 */

const Analysis = require('../models/Analysis');
const BlockRule = require('../models/BlockRule');
const { parsePcapFile } = require('./pcapParser');
const { parsePacket, PROTOCOL } = require('./packetParser');
const { inspect, APP_TYPES, classifyDomain } = require('./dpiEngine');

/**
 * Check if a packet should be blocked based on active rules
 */
function isBlocked(parsedPacket, dpiResult, rules) {
  for (const rule of rules) {
    if (!rule.active) continue;

    switch (rule.type) {
      case 'ip':
        if (parsedPacket.srcIp === rule.value || parsedPacket.destIp === rule.value) {
          return true;
        }
        break;

      case 'domain':
        if (dpiResult.sni && dpiResult.sni.toLowerCase().includes(rule.value.toLowerCase())) {
          return true;
        }
        break;

      case 'app':
        if (dpiResult.appType.toLowerCase() === rule.value.toLowerCase()) {
          return true;
        }
        break;
    }
  }
  return false;
}

/**
 * Run the full analysis pipeline
 * @param {string} analysisId - MongoDB document ID
 * @param {string} filePath - Path to uploaded .pcap file
 * @param {object} io - Socket.IO instance for progress updates
 */
async function runAnalysis(analysisId, filePath, io) {
  try {
    // Emit start
    io?.emit('analysis:progress', { analysisId, status: 'processing', progress: 0, message: 'Starting analysis...' });

    // Step 1: Parse PCAP file
    io?.emit('analysis:progress', { analysisId, status: 'processing', progress: 5, message: 'Reading PCAP file...' });
    const { globalHeader, packets } = parsePcapFile(filePath);

    // Step 2: Load active block rules
    const rules = await BlockRule.find({ active: true });

    // Step 3: Process each packet
    const flows = {};
    const appCounts = {};
    const protocolCounts = {};
    const detectedDomains = [];
    const packetSummaries = [];
    let totalBytes = 0;
    let tcpCount = 0;
    let udpCount = 0;
    let otherCount = 0;
    let parsedCount = 0;
    let forwarded = 0;
    let dropped = 0;

    const totalPackets = packets.length;

    for (let i = 0; i < totalPackets; i++) {
      const { header, data } = packets[i];

      // Progress update every 10% of packets
      if (i % Math.max(1, Math.floor(totalPackets / 10)) === 0) {
        const progress = 10 + Math.floor((i / totalPackets) * 80);
        io?.emit('analysis:progress', {
          analysisId,
          status: 'processing',
          progress,
          message: `Analyzing packet ${i + 1}/${totalPackets}...`,
        });
      }

      // Parse packet
      const parsed = parsePacket(data, i, header);
      if (!parsed) continue;
      parsedCount++;
      totalBytes += data.length;

      // Track protocol counts
      if (parsed.protocol === PROTOCOL.TCP) tcpCount++;
      else if (parsed.protocol === PROTOCOL.UDP) udpCount++;
      else otherCount++;

      protocolCounts[parsed.protocolName] = (protocolCounts[parsed.protocolName] || 0) + 1;

      // DPI inspection
      const dpi = inspect(data, parsed);

      // Flow tracking
      if (!flows[parsed.fiveTuple]) {
        flows[parsed.fiveTuple] = {
          fiveTuple: parsed.fiveTuple,
          srcIp: parsed.srcIp,
          destIp: parsed.destIp,
          srcPort: parsed.srcPort,
          destPort: parsed.destPort,
          protocol: parsed.protocolName,
          sni: dpi.sni || '',
          appType: dpi.appType,
          packets: 0,
          bytes: 0,
          blocked: false,
        };
      }

      const flow = flows[parsed.fiveTuple];
      flow.packets++;
      flow.bytes += data.length;

      // Update flow with DPI info
      if (dpi.sni && !flow.sni) {
        flow.sni = dpi.sni;
        flow.appType = dpi.appType;
      }

      // Check blocking
      const blocked = isBlocked(parsed, { ...dpi, sni: flow.sni || dpi.sni, appType: flow.appType || dpi.appType }, rules);
      if (blocked) {
        flow.blocked = true;
        dropped++;
      } else {
        forwarded++;
      }

      // App counts
      const app = flow.appType || dpi.appType;
      appCounts[app] = (appCounts[app] || 0) + 1;

      // Detected domains (unique)
      if (dpi.sni && !detectedDomains.find((d) => d.domain === dpi.sni)) {
        detectedDomains.push({ domain: dpi.sni, appType: dpi.appType });
      }

      // Packet summary (cap at 5000 for DB performance)
      if (packetSummaries.length < 5000) {
        packetSummaries.push({
          index: i,
          timestamp: parsed.timestamp,
          length: parsed.length,
          srcIp: parsed.srcIp,
          destIp: parsed.destIp,
          srcPort: parsed.srcPort,
          destPort: parsed.destPort,
          protocol: parsed.protocol,
          protocolName: parsed.protocolName,
          tcpFlags: parsed.tcpFlags,
          sni: dpi.sni || flow.sni || '',
          appType: flow.appType || dpi.appType,
          blocked,
        });
      }
    }

    // Step 4: Save results to MongoDB
    io?.emit('analysis:progress', { analysisId, status: 'processing', progress: 95, message: 'Saving results...' });

    const flowArray = Object.values(flows);

    await Analysis.findByIdAndUpdate(analysisId, {
      pcapVersion: globalHeader.version,
      linkType: globalHeader.linkTypeName,
      stats: {
        totalPackets,
        parsedPackets: parsedCount,
        totalBytes,
        tcpPackets: tcpCount,
        udpPackets: udpCount,
        otherPackets: otherCount,
        totalFlows: flowArray.length,
        forwarded,
        dropped,
      },
      appBreakdown: appCounts,
      protocolBreakdown: protocolCounts,
      detectedDomains,
      flows: flowArray,
      packets: packetSummaries,
      status: 'completed',
      completedAt: Date.now(),
    });

    // Emit completion
    io?.emit('analysis:progress', {
      analysisId,
      status: 'completed',
      progress: 100,
      message: 'Analysis complete!',
    });

    console.log(`✅ Analysis ${analysisId} completed: ${parsedCount} packets, ${flowArray.length} flows`);

  } catch (err) {
    console.error(`❌ Analysis ${analysisId} failed:`, err.message);

    await Analysis.findByIdAndUpdate(analysisId, {
      status: 'failed',
      error: err.message,
    });

    io?.emit('analysis:progress', {
      analysisId,
      status: 'failed',
      progress: 0,
      message: `Analysis failed: ${err.message}`,
    });
  }
}

module.exports = { runAnalysis };
