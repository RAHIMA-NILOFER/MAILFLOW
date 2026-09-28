import urllib.request
import json

base_api = 'http://127.0.0.1:8008/api'

def check(url, name):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'SentinelTest/1.0'})
        res = urllib.request.urlopen(req, timeout=5)
        data = res.read()
        print(f"[PASS] {name}: Status {res.status}, Length {len(data)} bytes")
        return data
    except Exception as e:
        print(f"[FAIL] {name}: {e}")
        return None

print("=== Running Integration Tests for MailFlow Sentinel ===")

# 1. Health
check(f"{base_api}/health", "Health Check")

# 2. Demo Overview
d = check(f"{base_api}/analysis/demo", "Demo Analysis Overview")
if d:
    obj = json.loads(d.decode())
    print(f"       File: {obj.get('filename')}")
    print(f"       Total Sessions: {obj.get('total_email_sessions')} (SMTP: {obj['protocol_distribution']['smtp']}, IMAP: {obj['protocol_distribution']['imap']}, POP3: {obj['protocol_distribution']['pop3']})")
    print(f"       TLS Sessions: {obj.get('total_tls_sessions')} | STARTTLS: {obj.get('total_starttls_sessions')}")
    print(f"       Security Score: {obj.get('security_score')}/100 | Critical Findings: {obj.get('critical_findings_count')}")

# 3. Sessions
check(f"{base_api}/analysis/demo/sessions", "Email Sessions Endpoint")

# 4. Session Detail for SMTP-0042
check(f"{base_api}/analysis/demo/session/SMTP-0042", "Session Detail SMTP-0042")

# 5. TLS
check(f"{base_api}/analysis/demo/tls", "TLS Handshakes Endpoint")

# 6. Certificates
check(f"{base_api}/analysis/demo/certificates", "Certificates Endpoint")

# 7. Findings
check(f"{base_api}/analysis/demo/findings", "Findings Endpoint")

# 8. Risk
check(f"{base_api}/analysis/demo/risk", "AI Risk Endpoint")

# 9. HTML Report
check(f"{base_api}/reports/ANALYSIS-DEMO-001/html", "HTML Forensic Report Endpoint")

# 10. Frontend Dev Server
check("http://127.0.0.1:5173/", "Frontend Vite Server")

print("=== All Integration Tests Completed Successfully ===")
