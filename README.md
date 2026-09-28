# MAILFLOW SENTINEL
### Passive Email Cryptographic Forensics & AI-Assisted Risk Analysis Platform

**MailFlow Sentinel** is a defensive, passive digital forensic platform engineered to analyze captured PCAP files containing SMTP, IMAP, and POP3 network traffic. The platform reconstructs email streams, audits STARTTLS and TLS 1.3/1.2 handshakes, inspects X.509 certificate trust chains, flags cryptographic weaknesses (such as deprecated TLS versions, weak ciphers like 3DES/RC4, missing Perfect Forward Secrecy, and expired certificates), and calculates transparent, explainable AI risk assessments.

---

## Strict Defensive Forensics Guarantee
MailFlow Sentinel operates **exclusively as a passive network forensic analyzer**. It analyzes recorded PCAP captures without packet injection, active scanning, credential harvesting, MITM interception, or traffic modification.

---

## Key Modules & Capabilities

1. **SOC Overview Dashboard**:
   - 8 Real-time KPI Cards: Total PCAP Packets (`48,392`), Email Sessions (`127`), TLS Sessions (`109`), STARTTLS Sessions (`103`), Certificates Analyzed (`5`), Critical Findings (`3`), High-Risk Sessions (`12`), Security Posture Score (`71/100`).
   - Interactive charts for Protocol Distribution (SMTP, IMAP, POP3), TLS Version Distribution, Risk Classification, and Cryptographic Weaknesses.
   - Suspicious Event Chronological Timeline with severity filtering.

2. **PCAP Ingestion & Analysis Engine**:
   - Drag-and-drop PCAP/PCAPNG/CAP file upload with SHA-256 hash generation and size validation.
   - 9-Stage live analysis execution pipeline animation & backend stream dissection.

3. **Email Session Forensic Reconstruction**:
   - Searchable, sortable, filterable forensic data table with multi-protocol filtering (SMTP, IMAP, POP3), Risk level, and TLS status.
   - CSV and JSON session export.

4. **Forensic Stream Inspector & Communication Ladder**:
   - Step-by-step Client-Server communication flow visualization highlighting plaintext-to-encrypted state transitions (TCP 3-Way Handshake &rarr; EHLO/CAPABILITY &rarr; STARTTLS &rarr; TLS ClientHello/ServerHello &rarr; Encrypted Application Data).

5. **Deep TLS & Cryptographic Audit**:
   - Analysis of TLS Version, Cipher Suite, Key Exchange (ECDHE vs Static RSA), Authentication, AEAD Encryption, and Hash integrity.
   - RFC 8996 deprecation compliance checks (flagging TLS 1.0/1.1, Sweet32 3DES, RC4, and Missing PFS).

6. **X.509 Certificate Chain Analyzer**:
   - Interactive 3-Tier Certificate Chain visualization (`Root CA` &rarr; `Intermediate CA` &rarr; `Server Certificate`).
   - 8-point cryptographic validation checklist (Validity period, Hostname/SAN match, Chain completeness, Key length $\ge$ 2048-bit, Signature algorithm, Expiration countdown).

7. **Cryptographic Findings Management**:
   - Structured registry (`CRYPTO-001` through `CRYPTO-009`) with CWE mappings, CVSS scores, observed forensic evidence, and actionable remediation guidelines.

8. **Explainable AI Risk Engine**:
   - Transparent feature attribution breakdown chart (`+25` TLS Version, `+20` Cipher Strength, `+15` Certificate, `+10` Key Exchange, `+10` STARTTLS, `+12` Anomaly Score).
   - "Why This Session Was Flagged" diagnostic section and 5-dimensional Radar risk profile.

9. **2D Threat Prioritization Matrix**:
   - Interactive Impact vs Likelihood / Exploitability matrix with clickable nodes and prioritized remediation backlog.

10. **Security Posture & Compliance**:
    - Circular Posture Score gauge (`71/100`), 7-pillar breakdown, previous comparison delta, and prioritized recommendations.

11. **Forensic Report Generation**:
    - Download full standalone styled HTML forensic dossiers, export machine-readable JSON, print executive PDF briefings, or inspect in-app live previews.

---

## Project Structure

```
mailflow_sentinal/
├── backend/
│   ├── analyzers/
│   │   ├── anomaly_detector.py      # Heuristic TLS & protocol anomaly detection
│   │   ├── cert_analyzer.py         # X.509 certificate validation and chain parsing
│   │   ├── crypto_engine.py         # Cryptographic weakness & findings generation
│   │   ├── pcap_parser.py           # Scapy passive PCAP stream reassembly
│   │   ├── risk_engine.py           # Explainable AI risk scoring engine
│   │   └── tls_analyzer.py          # TLS handshake & cipher suite audit
│   ├── models/
│   │   └── schemas.py               # Pydantic data models & schemas
│   ├── reports/
│   │   └── report_generator.py      # HTML & JSON report generator
│   ├── services/
│   │   ├── demo_service.py          # Enterprise mail capture demo dataset generator
│   │   └── pcap_service.py          # PCAP pipeline orchestrator
│   └── main.py                      # FastAPI REST server
├── frontend/
│   ├── src/
│   │   ├── components/              # Sidebar, TopBar, LandingPage
│   │   ├── views/                   # 11 Dedicated SOC views
│   │   ├── types/                   # TypeScript interfaces
│   │   ├── services/                # API client
│   │   ├── App.tsx                  # Master App component
│   │   └── index.css                # Custom SOC cybersecurity theme tokens
│   ├── package.json
│   └── vite.config.ts
└── test_endpoints.py                # Automated integration test suite
```

---

## Quickstart & Local Execution

### 1. Start the Backend Server (FastAPI)
```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8008
```

### 2. Start the Frontend Application (React + Vite)
```powershell
cd frontend
npm run dev -- --host 127.0.0.1 --port 5173
```

### 3. Open in Browser
Visit **`http://127.0.0.1:5173/`** to access the SOC platform. Click **"Enter Demo Analysis"** to immediately explore the pre-loaded enterprise forensic dataset.
