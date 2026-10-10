# CyberGuard – Product Cybersecurity Threat Modeling & RTM Platform

CyberGuard is an automated product cybersecurity assessment platform designed to shift security left into the early design phase of the Software Development Life Cycle (SDLC). It converts software architecture specifications into testable threat models, maps controls to OWASP standards, and generates an auditable Requirements Traceability Matrix (RTM).

---

## Key Features

- **Automated STRIDE Threat Modeling**: Identifies threats across Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege based on selected architecture components.
- **OWASP Control Mapping**: Links discovered threat vectors directly to OWASP Top 10 vulnerabilities, explicit technical controls, and acceptance criteria.
- **Requirements Traceability Matrix (RTM)**: Generates a living traceability table linking components, threats, controls, verification test cases, and real-time mitigation statuses (`Open`, `Mitigated`, `Verified`).
- **Audit-Ready CSV Export**: Instant export of compliance matrices for engineering and auditing teams.
- **SBOM & Dependency Vulnerability Scanner**: Analyzes software bill of materials manifests (`package.json`) using Python and the public Open Source Vulnerabilities (OSV) API to flag dependency CVEs.
- **Security Verification with Burp Suite**: Verification test plans designed for proxy interception, request tampering, and API boundary testing.

---

## Tech Stack

- **Frontend**: React.js, Vite, Tailwind CSS, Lucide React
- **Backend**: Node.js, Express.js, Mongoose
- **Database**: MongoDB
- **Security Scanner**: Python 3, OSV REST API
- **Testing & Verification**: Burp Suite Community Edition

---

## Getting Started

### 1. Prerequisites
- Node.js (v18+)
- Python (v3.9+)
- MongoDB (running locally on port 27017 or MongoDB Atlas connection string)

### 2. Backend Setup
```bash
cd server
npm install
python -m venv venv
# Windows:
.\venv\Scripts\activate
# macOS/Linux:
source venv/bin/activate
pip install requests
node server.js