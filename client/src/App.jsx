import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Shield, AlertTriangle, Upload, Download } from 'lucide-react';

const API = 'http://localhost:5000/api';

export default function App() {
  const [availableComponents, setAvailableComponents] = useState([]);
  const [selectedComponents, setSelectedComponents] = useState([]);
  const [projectName, setProjectName] = useState('');
  const [project, setProject] = useState(null);
  const [vulnerabilities, setVulnerabilities] = useState([]);

  useEffect(() => {
    axios.get(`${API}/components`)
      .then(res => setAvailableComponents(res.data))
      .catch(err => console.error("Ensure backend is running on port 5000", err));
  }, []);

  const handleCreateProject = async (e) => {
    e.preventDefault();
    if (!projectName || selectedComponents.length === 0) return;
    try {
      const res = await axios.post(`${API}/projects`, {
        name: projectName,
        components: selectedComponents
      });
      setProject(res.data);
    } catch (err) {
      alert("Failed to create project. Ensure backend server is running.");
    }
  };

  const updateStatus = async (rtmId, newStatus) => {
    try {
      const res = await axios.patch(`${API}/projects/${project._id}/rtm/${rtmId}`, { status: newStatus });
      setProject(res.data);
    } catch (err) {
      alert("Failed to update status");
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const formData = new FormData();
    formData.append('sbom', file);
    try {
      const res = await axios.post(`${API}/scan-sbom`, formData);
      setVulnerabilities(res.data);
    } catch (err) {
      alert('SBOM Scan failed. Ensure your backend server is running.');
    }
  };

  const exportToCSV = () => {
    if (!project || !project.rtm) return;

    const headers = [
      "Component",
      "STRIDE Category",
      "Identified Threat",
      "OWASP Mapping",
      "Security Control",
      "Acceptance Criteria",
      "Verification Test Case",
      "Status"
    ];

    const rows = project.rtm.map(item => [
      `"${(item.component || '').replace(/"/g, '""')}"`,
      `"${(item.strideCategory || '').replace(/"/g, '""')}"`,
      `"${(item.threat || '').replace(/"/g, '""')}"`,
      `"${(item.owaspMapping || '').replace(/"/g, '""')}"`,
      `"${(item.control || '').replace(/"/g, '""')}"`,
      `"${(item.acceptanceCriteria || '').replace(/"/g, '""')}"`,
      `"${(item.verificationTest || '').replace(/"/g, '""')}"`,
      `"${(item.status || '').replace(/"/g, '""')}"`
    ]);

    const csvContent = [headers.join(","), ...rows.map(e => e.join(","))].join("\n");
    const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `${project.name.replace(/\s+/g, '_')}_CyberGuard_RTM.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-8 font-sans">
      <header className="flex items-center space-x-3 mb-8 border-b border-slate-700 pb-4">
        <Shield className="text-emerald-400 w-8 h-8" />
        <h1 className="text-2xl font-bold">CyberGuard – Threat Modeling & RTM Platform</h1>
      </header>

      {!project ? (
        <div className="max-w-2xl bg-slate-800 p-6 rounded-lg border border-slate-700">
          <h2 className="text-lg font-semibold mb-4">Define System Architecture</h2>
          <form onSubmit={handleCreateProject} className="space-y-4">
            <div>
              <label className="block text-sm mb-1 text-slate-400">Application Name</label>
              <input
                type="text"
                value={projectName}
                onChange={e => setProjectName(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-white"
                placeholder="e.g., E-Commerce Core Services"
                required
              />
            </div>
            <div>
              <label className="block text-sm mb-2 text-slate-400">Select Architecture Components</label>
              <div className="space-y-2">
                {availableComponents.map(comp => (
                  <label key={comp} className="flex items-center space-x-2 text-sm cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selectedComponents.includes(comp)}
                      onChange={e => {
                        if (e.target.checked) setSelectedComponents([...selectedComponents, comp]);
                        else setSelectedComponents(selectedComponents.filter(c => c !== comp));
                      }}
                      className="rounded"
                    />
                    <span>{comp}</span>
                  </label>
                ))}
              </div>
            </div>
            <button type="submit" className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium py-2 px-4 rounded transition">
              Generate STRIDE RTM
            </button>
          </form>
        </div>
      ) : (
        <div className="space-y-8">
          <div className="flex justify-between items-center bg-slate-800 p-4 rounded-lg border border-slate-700">
            <div>
              <h2 className="text-xl font-bold">{project.name}</h2>
              <p className="text-sm text-slate-400">Components: {project.components.join(', ')}</p>
            </div>
            <div className="flex items-center space-x-3">
              <button
                onClick={exportToCSV}
                className="flex items-center space-x-2 bg-emerald-600 hover:bg-emerald-500 py-2 px-4 rounded text-sm font-medium transition cursor-pointer"
              >
                <Download className="w-4 h-4" />
                <span>Export RTM (CSV)</span>
              </button>
              <label className="flex items-center space-x-2 bg-indigo-600 hover:bg-indigo-500 py-2 px-4 rounded cursor-pointer text-sm font-medium transition">
                <Upload className="w-4 h-4" />
                <span>Scan package.json (SBOM)</span>
                <input type="file" onChange={handleFileUpload} accept=".json" className="hidden" />
              </label>
            </div>
          </div>

          {vulnerabilities.length > 0 && (
            <div className="bg-rose-950/40 border border-rose-800 p-4 rounded-lg">
              <h3 className="text-rose-400 font-semibold flex items-center gap-2 mb-2">
                <AlertTriangle className="w-5 h-5" /> Vulnerable Dependencies Identified (SBOM Analysis)
              </h3>
              <ul className="text-sm space-y-1">
                {vulnerabilities.map((v, idx) => (
                  <li key={idx} className="text-slate-300">
                    <strong className="text-white">{v.package}</strong> ({v.version}) — {v.cveCount} CVEs detected [{v.details.join(', ')}]
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="overflow-x-auto rounded-lg border border-slate-700">
            <table className="w-full text-left border-collapse bg-slate-800 text-sm">
              <thead className="bg-slate-700 text-slate-200">
                <tr>
                  <th className="p-3 border-b border-slate-600">Component</th>
                  <th className="p-3 border-b border-slate-600">STRIDE</th>
                  <th className="p-3 border-b border-slate-600">Threat</th>
                  <th className="p-3 border-b border-slate-600">Security Control</th>
                  <th className="p-3 border-b border-slate-600">Verification Test</th>
                  <th className="p-3 border-b border-slate-600">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700">
                {project.rtm.map(item => (
                  <tr key={item._id} className="hover:bg-slate-750">
                    <td className="p-3 font-medium">{item.component}</td>
                    <td className="p-3 text-amber-400 font-semibold">{item.strideCategory}</td>
                    <td className="p-3">{item.threat}</td>
                    <td className="p-3 text-slate-300">{item.control}</td>
                    <td className="p-3 text-indigo-300 font-mono text-xs">{item.verificationTest}</td>
                    <td className="p-3">
                      <select
                        value={item.status}
                        onChange={e => updateStatus(item._id, e.target.value)}
                        className="bg-slate-900 border border-slate-700 rounded p-1 text-xs text-white"
                      >
                        <option value="Open">Open</option>
                        <option value="Mitigated">Mitigated</option>
                        <option value="Verified">Verified</option>
                      </select>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}