const mongoose = require('mongoose');

// Sub-schemas for nested data
const FlowSchema = new mongoose.Schema({
  fiveTuple: String,
  srcIp: String,
  destIp: String,
  srcPort: Number,
  destPort: Number,
  protocol: String,
  sni: String,
  appType: String,
  packets: Number,
  bytes: Number,
  blocked: { type: Boolean, default: false },
}, { _id: false });

const PacketSummarySchema = new mongoose.Schema({
  index: Number,
  timestamp: String,
  length: Number,
  srcIp: String,
  destIp: String,
  srcPort: Number,
  destPort: Number,
  protocol: String,
  protocolName: String,
  tcpFlags: String,
  sni: String,
  appType: String,
  blocked: { type: Boolean, default: false },
}, { _id: false });

// Main Analysis schema
const AnalysisSchema = new mongoose.Schema({
  // File info
  filename: { type: String, required: true },
  originalName: { type: String, required: true },
  fileSize: Number,

  // PCAP metadata
  pcapVersion: String,
  linkType: String,

  // Summary statistics
  stats: {
    totalPackets: { type: Number, default: 0 },
    parsedPackets: { type: Number, default: 0 },
    totalBytes: { type: Number, default: 0 },
    tcpPackets: { type: Number, default: 0 },
    udpPackets: { type: Number, default: 0 },
    otherPackets: { type: Number, default: 0 },
    totalFlows: { type: Number, default: 0 },
    forwarded: { type: Number, default: 0 },
    dropped: { type: Number, default: 0 },
  },

  // App breakdown { appType: count }
  appBreakdown: { type: Map, of: Number, default: {} },

  // Detected domains/SNIs
  detectedDomains: [{
    domain: String,
    appType: String,
  }],

  // Protocol breakdown
  protocolBreakdown: { type: Map, of: Number, default: {} },

  // Flow details
  flows: [FlowSchema],

  // Packet summaries (capped for performance)
  packets: [PacketSummarySchema],

  // Status
  status: {
    type: String,
    enum: ['pending', 'processing', 'completed', 'failed'],
    default: 'pending',
  },
  error: String,

  // Timestamps
  createdAt: { type: Date, default: Date.now },
  completedAt: Date,
});

// Index for faster queries
AnalysisSchema.index({ createdAt: -1 });
AnalysisSchema.index({ status: 1 });

module.exports = mongoose.model('Analysis', AnalysisSchema);
