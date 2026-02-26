/**
 * Quick test: run the full DPI pipeline against a .pcap file
 * Usage: node test-pipeline.js <path-to-pcap>
 */

const path = require('path');
const { parsePcapFile } = require('./services/pcapParser');
const { parsePacket } = require('./services/packetParser');
const { inspect, APP_TYPES } = require('./services/dpiEngine');

const pcapPath = process.argv[2] || path.join(__dirname, '..', '..', 'Packet_analyser', 'Packet_analyzer', 'test_dpi.pcap');

console.log(`\n🔍 PacketVision — DPI Pipeline Test`);
console.log(`📂 File: ${pcapPath}\n`);

try {
  // Step 1: Parse PCAP
  const { globalHeader, packets } = parsePcapFile(pcapPath);
  console.log(`📋 PCAP v${globalHeader.version} | ${globalHeader.linkTypeName} | ${packets.length} packets\n`);

  // Step 2 & 3: Parse each packet + DPI
  const flows = {};
  const appCounts = {};
  const detectedSNIs = [];
  let parsedCount = 0;

  for (let i = 0; i < packets.length; i++) {
    const { header, data } = packets[i];
    const parsed = parsePacket(data, i, header);
    if (!parsed) continue;

    parsedCount++;

    // DPI inspection
    const dpi = inspect(data, parsed);

    // Track flows
    if (!flows[parsed.fiveTuple]) {
      flows[parsed.fiveTuple] = {
        fiveTuple: parsed.fiveTuple,
        srcIp: parsed.srcIp,
        destIp: parsed.destIp,
        srcPort: parsed.srcPort,
        destPort: parsed.destPort,
        protocol: parsed.protocolName,
        sni: dpi.sni,
        appType: dpi.appType,
        packets: 0,
      };
    }

    const flow = flows[parsed.fiveTuple];
    flow.packets++;

    // Update flow with DPI results if we found something
    if (dpi.sni && !flow.sni) {
      flow.sni = dpi.sni;
      flow.appType = dpi.appType;
    }

    // Count apps
    const app = flow.appType || dpi.appType;
    appCounts[app] = (appCounts[app] || 0) + 1;

    if (dpi.sni && !detectedSNIs.find(s => s.sni === dpi.sni)) {
      detectedSNIs.push({ sni: dpi.sni, app: dpi.appType });
    }
  }

  // Print results
  console.log(`✅ Parsed: ${parsedCount}/${packets.length} packets`);
  console.log(`🔗 Flows: ${Object.keys(flows).length}\n`);

  console.log('📊 Application Breakdown:');
  const sorted = Object.entries(appCounts).sort((a, b) => b[1] - a[1]);
  for (const [app, count] of sorted) {
    const pct = ((count / parsedCount) * 100).toFixed(1);
    console.log(`   ${app.padEnd(15)} ${String(count).padStart(4)} packets  (${pct}%)`);
  }

  console.log('\n🌐 Detected Domains/SNIs:');
  for (const { sni, app } of detectedSNIs) {
    console.log(`   ${sni} → ${app}`);
  }

  console.log('\n✨ Pipeline test completed successfully!');
} catch (err) {
  console.error(`❌ Error: ${err.message}`);
  process.exit(1);
}
