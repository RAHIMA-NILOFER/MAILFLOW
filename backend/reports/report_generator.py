"""
Forensic Report Generator for MailFlow Sentinel
Generates executive summaries, full technical forensic HTML documents, and JSON exports.
"""
from typing import Dict, Any
from backend.models.schemas import PCAPAnalysis

def generate_html_report(analysis: PCAPAnalysis) -> str:
    """Generate a high-assurance, professional dark/light SOC forensic report in self-contained HTML."""
    
    findings_rows = ""
    for f in analysis.findings:
        sev_color = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#3b82f6",
            "INFO": "#94a3b8"
        }.get(f.severity, "#94a3b8")
        
        findings_rows += f"""
        <tr style="border-bottom: 1px solid #1e293b;">
            <td style="padding: 12px; font-weight: 600; font-family: monospace; color: #38bdf8;">{f.id}</td>
            <td style="padding: 12px;"><span style="background: {sev_color}22; color: {sev_color}; padding: 3px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; border: 1px solid {sev_color}55;">{f.severity}</span></td>
            <td style="padding: 12px; font-weight: 600; color: #f8fafc;">{f.title}</td>
            <td style="padding: 12px; font-family: monospace; color: #94a3b8;">{f.session_id}</td>
            <td style="padding: 12px; color: #cbd5e1; font-size: 12px;">{f.evidence_observed}</td>
            <td style="padding: 12px; color: #34d399; font-size: 12px;">{f.recommendation}</td>
        </tr>
        """

    actions_rows = ""
    if analysis.security_posture:
        for action in analysis.security_posture.top_recommended_actions:
            actions_rows += f"""
            <li style="margin-bottom: 12px; padding: 12px; background: #0f172a; border-left: 4px solid #0284c7; border-radius: 4px;">
                <div style="font-weight: 700; color: #e2e8f0; font-size: 14px;">Priority {action.get('priority')}: {action.get('title')}</div>
                <div style="color: #94a3b8; font-size: 13px; margin-top: 4px;">{action.get('action')}</div>
                <div style="margin-top: 6px; font-size: 11px; color: #38bdf8;">Effort: <strong>{action.get('effort')}</strong> | Impact: <strong>{action.get('impact')}</strong></div>
            </li>
            """

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MailFlow Sentinel - Cryptographic Forensic Report ({analysis.filename})</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #0b0f19;
            color: #f1f5f9;
            margin: 0;
            padding: 30px;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            border-bottom: 2px solid #0284c7;
            padding-bottom: 20px;
            margin-bottom: 25px;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
        }}
        .logo-title {{
            font-size: 24px;
            font-weight: 800;
            letter-spacing: 1px;
            color: #38bdf8;
            text-transform: uppercase;
        }}
        .subtitle {{
            font-size: 13px;
            color: #94a3b8;
            margin-top: 4px;
        }}
        .badge {{
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        .badge-demo {{ background: #f59e0b22; color: #fbbf24; border: 1px solid #f59e0b66; }}
        .badge-live {{ background: #10b98122; color: #34d399; border: 1px solid #10b98166; }}
        .grid-4 {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 25px;
        }}
        .card {{
            background: #111827;
            border: 1px solid #1f2937;
            border-radius: 8px;
            padding: 16px;
        }}
        .card-label {{
            font-size: 12px;
            color: #9ca3af;
            text-transform: uppercase;
            font-weight: 600;
        }}
        .card-value {{
            font-size: 26px;
            font-weight: 700;
            color: #f9fafb;
            margin-top: 6px;
        }}
        .section-title {{
            font-size: 18px;
            font-weight: 700;
            color: #38bdf8;
            margin-top: 30px;
            margin-bottom: 15px;
            border-left: 4px solid #0284c7;
            padding-left: 10px;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: #111827;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid #1f2937;
        }}
        th {{
            background: #1f2937;
            text-align: left;
            padding: 12px;
            font-size: 12px;
            text-transform: uppercase;
            color: #94a3b8;
            font-weight: 700;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #1f2937;
            text-align: center;
            font-size: 12px;
            color: #64748b;
        }}
        @media print {{
            body {{ background: #ffffff; color: #0f172a; padding: 10px; }}
            .card {{ background: #f8fafc; border: 1px solid #e2e8f0; }}
            table {{ background: #ffffff; border: 1px solid #cbd5e1; }}
            th {{ background: #f1f5f9; color: #334155; }}
            tr td {{ color: #0f172a !important; }}
            .logo-title {{ color: #0284c7; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="logo-title">MAILFLOW SENTINEL</div>
                <div class="subtitle">Passive Email Cryptographic Forensics & AI-Assisted Risk Report</div>
                <div style="margin-top: 8px; font-size: 12px; color: #64748b;">
                    File: <strong style="color: #cbd5e1;">{analysis.filename}</strong> | SHA256: <code style="color: #38bdf8;">{analysis.sha256_hash[:20]}...</code> | Analyzed: {analysis.upload_timestamp}
                </div>
            </div>
            <div>
                <span class="badge {'badge-demo' if analysis.is_demo else 'badge-live'}">
                    {'DEMO ANALYSIS' if analysis.is_demo else 'PCAP LIVE FORENSIC AUDIT'}
                </span>
            </div>
        </div>

        <div class="grid-4">
            <div class="card">
                <div class="card-label">Security Posture Score</div>
                <div class="card-value" style="color: {'#34d399' if analysis.security_score >= 80 else ('#fbbf24' if analysis.security_score >= 60 else '#ef4444')}">{analysis.security_score}/100</div>
                <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">Rating: {analysis.risk_assessment.posture_rating if analysis.risk_assessment else 'Moderate'}</div>
            </div>
            <div class="card">
                <div class="card-label">Total Email Sessions</div>
                <div class="card-value">{analysis.total_email_sessions}</div>
                <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">SMTP: {analysis.protocol_distribution.smtp} | IMAP: {analysis.protocol_distribution.imap} | POP3: {analysis.protocol_distribution.pop3}</div>
            </div>
            <div class="card">
                <div class="card-label">TLS / STARTTLS Coverage</div>
                <div class="card-value">{analysis.total_tls_sessions} <span style="font-size: 14px; color: #94a3b8;">/ {analysis.total_email_sessions}</span></div>
                <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">{analysis.total_starttls_sessions} STARTTLS Transitions</div>
            </div>
            <div class="card">
                <div class="card-label">Critical / High Findings</div>
                <div class="card-value" style="color: #ef4444;">{analysis.critical_findings_count} <span style="font-size: 18px; color: #f97316;">/ {analysis.high_findings_count}</span></div>
                <div style="font-size: 11px; color: #94a3b8; margin-top: 4px;">{analysis.medium_findings_count} Medium severity issues</div>
            </div>
        </div>

        <div class="section-title">Cryptographic Weaknesses & Forensic Findings</div>
        <table>
            <thead>
                <tr>
                    <th>ID</th>
                    <th>Severity</th>
                    <th>Finding Title</th>
                    <th>Session Ref</th>
                    <th>Observed Forensic Evidence</th>
                    <th>Remediation Action</th>
                </tr>
            </thead>
            <tbody>
                {findings_rows}
            </tbody>
        </table>

        <div class="section-title">Top Actionable Security Recommendations</div>
        <ul style="list-style: none; padding-left: 0;">
            {actions_rows}
        </ul>

        <div class="footer">
            Generated by <strong>MailFlow Sentinel</strong> Passive Network Forensic Framework &bull; Passive PCAP Analysis Engine &bull; Confidential
        </div>
    </div>
</body>
</html>
    """
    return html
