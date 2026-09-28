import React, { useState } from 'react';
import {
  AlertTriangle,
  ShieldAlert,
  Search,
  Filter,
  ArrowUpRight,
  CheckCircle2,
  AlertOctagon,
  FileCode,
  Tag,
  ExternalLink,
  ChevronDown,
  ChevronUp
} from 'lucide-react';
import { Finding, PCAPAnalysis, Severity } from '../types';

interface CryptographicFindingsProps {
  analysis: PCAPAnalysis;
  onSelectSessionId?: (sessionId: string) => void;
}

export const CryptographicFindings: React.FC<CryptographicFindingsProps> = ({
  analysis,
  onSelectSessionId
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [categoryFilter, setCategoryFilter] = useState('ALL');
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);

  const categories = Array.from(new Set(analysis.findings.map((f) => f.category)));

  const filteredFindings = analysis.findings.filter((finding) => {
    if (severityFilter !== 'ALL' && finding.severity !== severityFilter) return false;
    if (categoryFilter !== 'ALL' && finding.category !== categoryFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchId = finding.id.toLowerCase().includes(term);
      const matchTitle = finding.title.toLowerCase().includes(term);
      const matchSession = finding.session_id.toLowerCase().includes(term);
      const matchRec = finding.recommendation.toLowerCase().includes(term);
      if (!matchId && !matchTitle && !matchSession && !matchRec) return false;
    }
    return true;
  });

  const getSeverityBadge = (severity: Severity) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-red-950/80 text-red-400 border-red-800/80';
      case 'HIGH':
        return 'bg-orange-950/80 text-orange-400 border-orange-800/80';
      case 'MEDIUM':
        return 'bg-amber-950/80 text-amber-400 border-amber-800/80';
      case 'LOW':
        return 'bg-blue-950/80 text-blue-400 border-blue-800/80';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner Overview */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-red-950 text-red-400 text-[11px] font-semibold mb-2 border border-red-800/40">
              <AlertOctagon className="w-3.5 h-3.5" />
              Vulnerability & Cryptographic Weakness Registry
            </div>
            <h2 className="text-xl font-bold text-white">Cryptographic Findings Management</h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Standardized forensic findings compiled from passive PCAP inspection, mapped to CWE security weaknesses, CVSS severity scores, and NIST/RFC remediation guidelines.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-mono px-3 py-1.5 rounded bg-red-950/60 border border-red-800/60 text-red-400 font-bold">
              {analysis.critical_findings_count} Critical
            </span>
            <span className="text-xs font-mono px-3 py-1.5 rounded bg-orange-950/60 border border-orange-800/60 text-orange-400 font-bold">
              {analysis.high_findings_count} High
            </span>
            <span className="text-xs font-mono px-3 py-1.5 rounded bg-amber-950/60 border border-amber-800/60 text-amber-400 font-bold">
              {analysis.medium_findings_count} Medium
            </span>
          </div>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-4 flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search findings by ID, title, session ID, or recommendation..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-[#080c16] border border-slate-700 rounded-md pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {/* Severity Filter */}
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-[#080c16] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical ({analysis.critical_findings_count})</option>
            <option value="HIGH">High ({analysis.high_findings_count})</option>
            <option value="MEDIUM">Medium ({analysis.medium_findings_count})</option>
            <option value="LOW">Low ({analysis.low_findings_count})</option>
          </select>

          {/* Category Filter */}
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value)}
            className="bg-[#080c16] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
          >
            <option value="ALL">All Categories</option>
            {categories.map((cat) => (
              <option key={cat} value={cat}>
                {cat}
              </option>
            ))}
          </select>
        </div>
      </div>

      {/* Findings Cards List */}
      <div className="space-y-3">
        {filteredFindings.length > 0 ? (
          filteredFindings.map((finding) => {
            const isExpanded = expandedFinding === finding.id;

            return (
              <div
                key={finding.id}
                className="bg-[#0d1424] border border-slate-800 rounded-lg p-4 hover:border-slate-700 transition-all text-xs"
              >
                {/* Header Row */}
                <div
                  onClick={() => setExpandedFinding(isExpanded ? null : finding.id)}
                  className="flex items-center justify-between cursor-pointer"
                >
                  <div className="flex items-center space-x-3">
                    <span className="font-mono font-bold text-sm text-cyan-400">
                      {finding.id}
                    </span>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded border ${getSeverityBadge(finding.severity)}`}>
                      {finding.severity}
                    </span>
                    <span className="text-sm font-bold text-white">{finding.title}</span>
                  </div>

                  <div className="flex items-center space-x-3">
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono text-[10px]">
                      {finding.session_id}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-slate-800 text-slate-400 text-[10px]">
                      {finding.category}
                    </span>
                    <button className="text-slate-400 hover:text-slate-200">
                      {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Always-visible Summary Row */}
                <div className="mt-2 text-slate-400 grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <span className="text-slate-400 text-[10px] uppercase font-bold">Observed Evidence:</span>
                    <div className="font-mono text-amber-300 text-[11px] mt-0.5 truncate">
                      {finding.evidence_observed}
                    </div>
                  </div>
                  <div>
                    <span className="text-slate-400 text-[10px] uppercase font-bold">Recommended Secure Value:</span>
                    <div className="font-mono text-emerald-400 text-[11px] mt-0.5 truncate">
                      {finding.expected_secure}
                    </div>
                  </div>
                </div>

                {/* Expanded Detailed View */}
                {isExpanded && (
                  <div className="mt-4 pt-4 border-t border-slate-800 space-y-3">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div className="p-3 rounded bg-[#080c16] border border-slate-800/80">
                        <div className="text-[10px] uppercase font-bold text-red-400">Impact & Exposure</div>
                        <div className="text-slate-300 text-[11px] mt-1 leading-relaxed">
                          {finding.impact}
                        </div>
                      </div>

                      <div className="p-3 rounded bg-[#080c16] border border-slate-800/80">
                        <div className="text-[10px] uppercase font-bold text-emerald-400">Actionable Remediation</div>
                        <div className="text-slate-300 text-[11px] mt-1 leading-relaxed">
                          {finding.recommendation}
                        </div>
                      </div>
                    </div>

                    <div className="p-2.5 rounded bg-black/40 border border-slate-800 font-mono text-[10px] text-slate-400 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <span>Stream Reference: <strong className="text-slate-200">{finding.packet_stream_ref}</strong></span>
                      <span>CWE Identifier: <strong className="text-cyan-300">{finding.cwe_id || 'CWE-326'}</strong> | CVSS v3.1: <strong className="text-amber-400">{finding.cvss_score || 7.5}</strong></span>
                    </div>
                  </div>
                )}
              </div>
            );
          })
        ) : (
          <div className="p-12 text-center text-xs text-slate-400 bg-[#0d1424] border border-slate-800 rounded-lg">
            No cryptographic findings match your search or filter options.
          </div>
        )}
      </div>
    </div>
  );
};
