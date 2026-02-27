const express = require('express');
const router = express.Router();
const BlockRule = require('../models/BlockRule');

/**
 * GET /api/rules
 * Get all block rules
 */
router.get('/', async (req, res) => {
  try {
    const rules = await BlockRule.find().sort({ createdAt: -1 });
    res.json(rules);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/rules
 * Create a new block rule
 */
router.post('/', async (req, res) => {
  try {
    const { type, value, description } = req.body;

    if (!type || !value) {
      return res.status(400).json({ error: 'type and value are required' });
    }

    if (!['ip', 'domain', 'app'].includes(type)) {
      return res.status(400).json({ error: 'type must be ip, domain, or app' });
    }

    const rule = new BlockRule({ type, value, description });
    await rule.save();

    res.status(201).json(rule);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ error: 'Rule already exists' });
    }
    res.status(500).json({ error: err.message });
  }
});

/**
 * PUT /api/rules/:id
 * Update a block rule (toggle active, change value, etc.)
 */
router.put('/:id', async (req, res) => {
  try {
    const { type, value, description, active } = req.body;

    const rule = await BlockRule.findByIdAndUpdate(
      req.params.id,
      { type, value, description, active, updatedAt: Date.now() },
      { new: true, runValidators: true }
    );

    if (!rule) {
      return res.status(404).json({ error: 'Rule not found' });
    }

    res.json(rule);
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ error: 'Rule already exists' });
    }
    res.status(500).json({ error: err.message });
  }
});

/**
 * DELETE /api/rules/:id
 * Delete a block rule
 */
router.delete('/:id', async (req, res) => {
  try {
    const rule = await BlockRule.findByIdAndDelete(req.params.id);
    if (!rule) {
      return res.status(404).json({ error: 'Rule not found' });
    }
    res.json({ message: 'Rule deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
