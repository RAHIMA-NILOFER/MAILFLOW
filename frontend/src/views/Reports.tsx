import React, { useState } from 'react';
import {
  FileText,
  Download,
  Printer,
  FileCode,
  FileSpreadsheet,
  CheckCircle2,
  Sparkles,
  ExternalLink,
  ShieldCheck,
  Eye
} from 'lucide-react';
import { PCAPAnalysis } from '../types';

interface ReportsProps {
  analysis: PCAPAnalysis;
}

export const Reports: React.FC<ReportsProps> = ({ analysis }) => {
  const [showPreview, setShowPreview] = useState(false);

  const exportJSON = () => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(analysis, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute('href', dataStr);
    downloadAnchor.setAttribute('download', `mailflow_forensic_report_${analysis.id}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  const exportHTML = () => {
    // Direct link to backend endpoint or generate local blob
    const url = `/api/reports/${analysis.id}/html`;
    window.open(url, '_blank');
  };

  const printReport = () => {
    window.open(`/api/reports/${analysis.id}/pdf`, '_blank');
  };

  return (
    <div className="space-y-6 pb-12 max-w-5xl mx-auto">
      {/* Top Banner Header */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-cyan-950 text-cyan-300 text-[11px] font-semibold mb-2 border border-cyan-800/40">
              <FileText className="w-3.5 h-3.5" />
              Forensic Reporting & Export Center
            </div>
            <h2 className="text-xl font-bold text-white">Cryptographic Forensic Audit Reports</h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Generate executive compliance summaries, complete technical evidence dossiers, and machine-readable JSON exports suitable for digital forensics, incident response, and regulatory audits.
            </p>
          </div>
        </div>
      </div>

      {/* Export Options Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {/* HTML Report */}
        <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5 flex flex-col justify-between space-y-4">
          <div>
            <div className="w-10 h-10 rounded-lg bg-cyan-950 border border-cyan-800/50 flex items-center justify-center text-cyan-400 mb-3">
              <FileText className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-bold text-white">Full Forensic HTML Dossier</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Self-contained interactive HTML document containing full session transcripts, certificate chains, and findings.
            </p>
          </div>
          <button
            onClick={exportHTML}
            className="w-full py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold rounded text-xs flex items-center justify-center gap-1.5 transition-all shadow-md shadow-cyan-950/40"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Open / Download HTML</span>
          </button>
        </div>

        {/* JSON Export */}
        <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5 flex flex-col justify-between space-y-4">
          <div>
            <div className="w-10 h-10 rounded-lg bg-blue-950 border border-blue-800/50 flex items-center justify-center text-blue-400 mb-3">
              <FileCode className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-bold text-white">Raw JSON Forensic Data</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Complete machine-readable JSON object including all reconstructed streams, risk scores, and X.509 metadata.
            </p>
          </div>
          <button
            onClick={exportJSON}
            className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold rounded text-xs border border-slate-700 flex items-center justify-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export Raw JSON</span>
          </button>
        </div>

        {/* Print / PDF Document */}
        <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5 flex flex-col justify-between space-y-4">
          <div>
            <div className="w-10 h-10 rounded-lg bg-emerald-950 border border-emerald-800/50 flex items-center justify-center text-emerald-400 mb-3">
              <Printer className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-bold text-white">Print-Ready Executive PDF</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Formatted document optimized for executive briefing, security audits, and board presentations.
            </p>
          </div>
          <button
            onClick={printReport}
            className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 font-semibold rounded text-xs border border-slate-700 flex items-center justify-center gap-1.5 transition-colors"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print to PDF</span>
          </button>
        </div>

        {/* Live Preview Toggle */}
        <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5 flex flex-col justify-between space-y-4">
          <div>
            <div className="w-10 h-10 rounded-lg bg-purple-950 border border-purple-800/50 flex items-center justify-center text-purple-400 mb-3">
              <Eye className="w-5 h-5" />
            </div>
            <h3 className="text-sm font-bold text-white">In-App Report Viewer</h3>
            <p className="text-xs text-slate-400 mt-1 leading-relaxed">
              Preview the executive audit document directly inside the SOC workstation interface.
            </p>
          </div>
          <button
            onClick={() => setShowPreview(!showPreview)}
            className="w-full py-2 bg-purple-950/80 hover:bg-purple-900/80 text-purple-300 font-semibold rounded text-xs border border-purple-800/60 flex items-center justify-center gap-1.5 transition-colors"
          >
            <Eye className="w-3.5 h-3.5" />
            <span>{showPreview ? 'Hide Preview' : 'Show Live Preview'}</span>
          </button>
        </div>
      </div>

      {/* Embedded Live Report Preview Frame */}
      {showPreview && (
        <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-6 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyan-400" />
              Live Executive Report Preview ({analysis.filename})
            </div>
            <button
              onClick={() => setShowPreview(false)}
              className="text-xs text-slate-400 hover:text-slate-200"
            >
              Close
            </button>
          </div>

          <div className="bg-[#090e1a] border border-slate-800 rounded-lg p-6 space-y-6 text-xs text-slate-300">
            <div className="flex justify-between items-start pb-4 border-b border-slate-800">
              <div>
                <h1 className="text-lg font-bold text-white">MAILFLOW SENTINEL FORENSIC AUDIT</h1>
                <div className="text-slate-400 text-[11px] mt-1">
                  Passive PCAP Email Cryptographic & Vulnerability Report
                </div>
              </div>
              <div className="text-right font-mono text-[11px]">
                <div>File: <strong className="text-cyan-300">{analysis.filename}</strong></div>
                <div>Hash: <strong className="text-slate-400">{analysis.sha256_hash.substring(0, 16)}...</strong></div>
                <div>Date: <strong className="text-slate-300">{analysis.upload_timestamp}</strong></div>
              </div>
            </div>

            {/* Metric Summary */}
            <div className="grid grid-cols-4 gap-3 text-center">
              <div className="p-3 bg-[#0d1424] rounded border border-slate-800">
                <div className="text-slate-400 text-[10px]">Score</div>
                <div className="text-xl font-bold font-mono text-cyan-300 mt-1">{analysis.security_score}/100</div>
              </div>
              <div className="p-3 bg-[#0d1424] rounded border border-slate-800">
                <div className="text-slate-400 text-[10px]">Total Sessions</div>
                <div className="text-xl font-bold font-mono text-white mt-1">{analysis.total_email_sessions}</div>
              </div>
              <div className="p-3 bg-[#0d1424] rounded border border-slate-800">
                <div className="text-slate-400 text-[10px]">TLS Sessions</div>
                <div className="text-xl font-bold font-mono text-emerald-400 mt-1">{analysis.total_tls_sessions}</div>
              </div>
              <div className="p-3 bg-[#0d1424] rounded border border-slate-800">
                <div className="text-slate-400 text-[10px]">Critical Findings</div>
                <div className="text-xl font-bold font-mono text-red-400 mt-1">{analysis.critical_findings_count}</div>
              </div>
            </div>

            {/* Findings preview table */}
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
                Executive Findings Summary
              </div>
              <div className="space-y-2">
                {analysis.findings.slice(0, 5).map((f) => (
                  <div key={f.id} className="p-3 bg-[#0d1424] rounded border border-slate-800 flex justify-between items-center text-xs">
                    <div>
                      <span className="font-mono text-cyan-400 font-bold mr-2">{f.id}</span>
                      <span className="text-white font-semibold">{f.title}</span>
                      <div className="text-slate-400 text-[11px] mt-0.5">{f.recommendation}</div>
                    </div>
                    <span className="text-[10px] font-bold px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800">
                      {f.severity}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
