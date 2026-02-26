const mongoose = require('mongoose');

const BlockRuleSchema = new mongoose.Schema({
  // Rule type: 'ip', 'domain', or 'app'
  type: {
    type: String,
    enum: ['ip', 'domain', 'app'],
    required: true,
  },

  // The value to block (e.g., '192.168.1.50', 'facebook.com', 'YouTube')
  value: {
    type: String,
    required: true,
    trim: true,
  },

  // Description (optional)
  description: {
    type: String,
    default: '',
  },

  // Enable/disable toggle
  active: {
    type: Boolean,
    default: true,
  },

  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// Auto-update the updatedAt field
BlockRuleSchema.pre('save', function (next) {
  this.updatedAt = Date.now();
  next();
});

// Compound index to prevent duplicates
BlockRuleSchema.index({ type: 1, value: 1 }, { unique: true });

module.exports = mongoose.model('BlockRule', BlockRuleSchema);
