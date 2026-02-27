const express = require('express');
const router = express.Router();
const upload = require('../middleware/upload');
const Analysis = require('../models/Analysis');
const { runAnalysis } = require('../services/analysisService');

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

    // Optionally delete the uploaded file
    const fs = require('fs');
    const path = require('path');
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
