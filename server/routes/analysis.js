const express = require('express');
const fs = require('fs');
const path = require('path');
const router = express.Router();
const upload = require('../middleware/upload');
const Analysis = require('../models/Analysis');
const BlockRule = require('../models/BlockRule');
const { runAnalysis } = require('../services/analysisService');
const { parsePcapFile, writePcapFile } = require('../services/pcapParser');
const { parsePacket } = require('../services/packetParser');
const { inspect } = require('../services/dpiEngine');

/**
 * POST /api/analysis/upload
 * Upload a .pcap file and start analysis
 */
router.post('/upload', upload.single('pcap'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded. Please select a .pcap file.' });
    }

    // Create analysis record
    const analysis = new Analysis({
      filename: req.file.filename,
      originalName: req.file.originalname,
      fileSize: req.file.size,
      status: 'processing',
    });
    await analysis.save();

    // Get Socket.IO instance for progress updates
    const io = req.app.get('io');

    // Run analysis asynchronously
    runAnalysis(analysis._id, req.file.path, io)
      .catch((err) => {
        console.error(`Analysis failed for ${analysis._id}:`, err.message);
      });

    res.status(201).json({
      message: 'File uploaded. Analysis started.',
      analysisId: analysis._id,
    });
  } catch (err) {
    console.error('Upload error:', err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/analysis
 * Get all analyses (summary view, sorted by newest first)
 */
router.get('/', async (req, res) => {
  try {
    const analyses = await Analysis.find()
      .select('originalName fileSize stats.totalPackets stats.totalFlows status createdAt completedAt appBreakdown')
      .sort({ createdAt: -1 })
      .limit(50);

    res.json(analyses);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/analysis/:id/export
 * Download a filtered .pcap with blocked packets removed
 */
router.get('/:id/export', async (req, res) => {
  try {
    const analysis = await Analysis.findById(req.params.id);
    if (!analysis) {
      return res.status(404).json({ error: 'Analysis not found' });
    }

    const inputPath = path.join(__dirname, '..', 'uploads', analysis.filename);
    if (!fs.existsSync(inputPath)) {
      return res.status(404).json({ error: 'Original PCAP file not found' });
    }

    // Load active block rules
    const rules = await BlockRule.find({ active: true });

    // Re-read the PCAP and filter
    const { packets } = parsePcapFile(inputPath);
    const filteredPackets = [];

    for (let i = 0; i < packets.length; i++) {
      const { header, data } = packets[i];
      const parsed = parsePacket(data, i, header);

      if (!parsed) {
        filteredPackets.push(packets[i]); // Keep unparseable packets
        continue;
      }

      const dpi = inspect(data, parsed);
      let blocked = false;

      for (const rule of rules) {
        if (!rule.active) continue;
        if (rule.type === 'ip' && (parsed.srcIp === rule.value || parsed.destIp === rule.value)) { blocked = true; break; }
        if (rule.type === 'domain' && dpi.sni && dpi.sni.toLowerCase().includes(rule.value.toLowerCase())) { blocked = true; break; }
        if (rule.type === 'app' && dpi.appType.toLowerCase() === rule.value.toLowerCase()) { blocked = true; break; }
      }

      if (!blocked) {
        filteredPackets.push(packets[i]);
      }
    }

    // Write the filtered pcap to a temp file
    const exportName = `filtered-${analysis.originalName}`;
    const exportPath = path.join(__dirname, '..', 'uploads', `export-${Date.now()}.pcap`);
    writePcapFile(exportPath, filteredPackets);

    // Stream it back and clean up
    res.setHeader('Content-Disposition', `attachment; filename="${exportName}"`);
    res.setHeader('Content-Type', 'application/octet-stream');

    const stream = fs.createReadStream(exportPath);
    stream.pipe(res);
    stream.on('end', () => {
      fs.unlink(exportPath, () => {}); // Cleanup temp file
    });
  } catch (err) {
    console.error('Export error:', err);
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/analysis/:id
 * Get full analysis details by ID
 */
router.get('/:id', async (req, res) => {
  try {
    const analysis = await Analysis.findById(req.params.id);
    if (!analysis) {
      return res.status(404).json({ error: 'Analysis not found' });
    }
    res.json(analysis);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /api/analysis/:id
 * Delete an analysis
 */
router.delete('/:id', async (req, res) => {
  try {
    const analysis = await Analysis.findByIdAndDelete(req.params.id);
    if (!analysis) {
      return res.status(404).json({ error: 'Analysis not found' });
    }

    const filePath = path.join(__dirname, '..', 'uploads', analysis.filename);
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    res.json({ message: 'Analysis deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
