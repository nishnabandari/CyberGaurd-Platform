const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const multer = require('multer');
const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');

const Project = require('./models/Project');
const { generateRTM, THREAT_RULES } = require('./engine/strideRules');

const app = express();
app.use(cors());
app.use(express.json());

const upload = multer({ dest: 'uploads/' });

mongoose.connect(process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/cyberguard')
  .then(() => console.log('Connected to MongoDB'))
  .catch(err => console.error('MongoDB connection failed:', err));

app.get('/api/components', (req, res) => {
  res.json(Object.keys(THREAT_RULES));
});

app.post('/api/projects', async (req, res) => {
  try {
    const { name, description, components } = req.body;
    const rtm = generateRTM(components);
    const project = new Project({ name, description, components, rtm });
    await project.save();
    res.status(201).json(project);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/projects/:projectId/rtm/:rtmId', async (req, res) => {
  try {
    const { status } = req.body;
    const project = await Project.findById(req.params.projectId);
    if (!project) return res.status(404).json({ error: 'Project not found' });

    const item = project.rtm.id(req.params.rtmId);
    if (!item) return res.status(404).json({ error: 'RTM Item not found' });

    item.status = status;
    await project.save();
    res.json(project);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/scan-sbom', upload.single('sbom'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

  const filePath = path.resolve(req.file.path);
  const pythonProc = spawn('python', ['scanner/sbom_analyzer.py', filePath]);

  let stdoutData = '';
  pythonProc.stdout.on('data', data => { stdoutData += data.toString(); });
  pythonProc.on('close', code => {
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    if (code !== 0) return res.status(500).json({ error: 'Vulnerability scan failed' });
    try {
      res.json(JSON.parse(stdoutData));
    } catch {
      res.json([]);
    }
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));