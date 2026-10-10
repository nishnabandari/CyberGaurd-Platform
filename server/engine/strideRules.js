const THREAT_RULES = {
  "Authentication Service": [
    {
      strideCategory: "Spoofing",
      threat: "Credential stuffing or weak session token forgery",
      owaspMapping: "A07:2021-Identification and Authentication Failures",
      control: "Enforce Argon2/bcrypt hashing, MFA, and RS256-signed JWTs with 15-min expiration",
      acceptanceCriteria: "Tokens invalid after expiry; brute force blocked after 5 attempts",
      verificationTest: "Burp Suite: Tamper JWT signature without secret; check for HTTP 401"
    },
    {
      strideCategory: "Elevation of Privilege",
      threat: "Privilege escalation via insecure role modification in claims",
      owaspMapping: "A01:2021-Broken Access Control",
      control: "Enforce strict Role-Based Access Control (RBAC) verified at the data layer",
      acceptanceCriteria: "Regular users receive 403 Forbidden when calling /admin endpoints",
      verificationTest: "Burp Suite: Swap Authorization header to non-admin token on administrative endpoints"
    }
  ],
  "API Gateway / REST Endpoints": [
    {
      strideCategory: "Denial of Service",
      threat: "Resource starvation through unthrottled API endpoint flooding",
      owaspMapping: "A04:2021-Insecure Design",
      control: "Implement IP and User-level rate limiting (e.g., 100 requests / 15 minutes)",
      acceptanceCriteria: "API returns HTTP 429 Too Many Requests when threshold exceeded",
      verificationTest: "Burp Intruder / curl loop: Send 150 consecutive requests rapidly; confirm 429"
    },
    {
      strideCategory: "Tampering",
      threat: "Parameter tampering or NoSQL/SQL injection via unvalidated input",
      owaspMapping: "A03:2021-Injection",
      control: "Strict schema validation using Joi/Zod and Mongoose parameterized queries",
      acceptanceCriteria: "Arbitrary operators ($ne, $gt, SQL strings) rejected with HTTP 400",
      verificationTest: "Burp Suite: Inject payload {\"username\": {\"$ne\": null}} in login body"
    }
  ],
  "Database / Storage": [
    {
      strideCategory: "Information Disclosure",
      threat: "Sensitive PII and secret exposure through unencrypted data storage",
      owaspMapping: "A02:2021-Cryptographic Failures",
      control: "Field-level AES-256 encryption at rest; TLS 1.3 in transit",
      acceptanceCriteria: "Direct database dumps reveal zero plaintext PII or secrets",
      verificationTest: "Direct DB query: Run mongo query to confirm fields are stored as ciphertext"
    },
    {
      strideCategory: "Repudiation",
      threat: "Actions cannot be traced to specific actors due to missing audit trails",
      owaspMapping: "A09:2021-Security Logging and Monitoring Failures",
      control: "Immutable append-only audit logging with timestamp, actor ID, and IP address",
      acceptanceCriteria: "All critical CRUD actions generate write-events in audit logs",
      verificationTest: "Inspect audit log collection following administrative record update"
    }
  ]
};

function generateRTM(selectedComponents) {
  let rtm = [];
  selectedComponents.forEach(comp => {
    if (THREAT_RULES[comp]) {
      THREAT_RULES[comp].forEach(rule => {
        rtm.push({ component: comp, ...rule, status: 'Open' });
      });
    }
  });
  return rtm;
}

module.exports = { generateRTM, THREAT_RULES };