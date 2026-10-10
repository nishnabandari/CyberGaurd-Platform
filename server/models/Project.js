const mongoose = require('mongoose');

const RTMItemSchema = new mongoose.Schema({
  component: { type: String, required: true },
  strideCategory: { type: String, enum: ['Spoofing', 'Tampering', 'Repudiation', 'Information Disclosure', 'Denial of Service', 'Elevation of Privilege'] },
  threat: { type: String, required: true },
  owaspMapping: { type: String, required: true },
  control: { type: String, required: true },
  acceptanceCriteria: { type: String, required: true },
  verificationTest: { type: String, required: true },
  status: { type: String, enum: ['Open', 'Mitigated', 'Verified'], default: 'Open' }
});

const ProjectSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: String,
  components: [String],
  rtm: [RTMItemSchema],
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('Project', ProjectSchema);