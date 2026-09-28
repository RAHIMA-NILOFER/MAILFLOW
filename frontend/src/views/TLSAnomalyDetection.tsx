import React, { useState } from 'react';
import {
  Radio,
  AlertTriangle,
  Activity,
  ShieldAlert,
  Clock,
  CheckCircle2,
  AlertOctagon,
  Search,
  Filter,
  Zap
} from 'lucide-react';
import { PCAPAnalysis, Anomaly } from '../types';

interface TLSAnomalyDetectionProps {
  analysis: PCAPAnalysis;
  onNavigateSession?: (sessionId: string) => void;
}

export const TLSAnomalyDetection: React.FC<TLSAnomalyDetectionProps> = ({
  analysis,
  onNavigateSession
}) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');

  const anomalies = analysis.anomalies || [];

  const filteredAnomalies = anomalies.filter((a) => {
    if (severityFilter !== 'ALL' && a.severity !== severityFilter) return false;
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      const matchType = a.anomaly_type.toLowerCase().includes(term);
      const matchSession = a.session_id.toLowerCase().includes(term);
      const matchExp = a.explanation.toLowerCase().includes(term);
      if (!matchType && !matchSession && !matchExp) return false;
    }
    return true;
  });

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner Header */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-cyan-950 text-cyan-300 text-[11px] font-semibold mb-2 border border-cyan-800/40">
              <Radio className="w-3.5 h-3.5 text-cyan-400" />
              Heuristic Behavior & Traffic Anomaly Detector
            </div>
            <h2 className="text-xl font-bold text-white">TLS & Protocol Anomaly Detection</h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Continuous inspection for behavioral deviations: opportunistic STARTTLS downgrade stripping, rare cipher selection, abnormal handshake timing latencies, and plaintext credential transmission.
            </p>
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs font-mono px-3 py-1.5 rounded bg-slate-900 border border-slate-800 text-slate-300">
              Total Anomalies: <strong className="text-red-400">{anomalies.length}</strong>
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
            placeholder="Search anomalies by type, session ID, or explanation..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full bg-[#080c16] border border-slate-700 rounded-md pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 font-mono"
          />
        </div>

        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="bg-[#080c16] border border-slate-700 rounded px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
        >
          <option value="ALL">All Severities</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
        </select>
      </div>

      {/* Anomalies List */}
      <div className="space-y-3">
        {filteredAnomalies.length > 0 ? (
          filteredAnomalies.map((anom) => (
            <div
              key={anom.id}
              className="bg-[#0d1424] border border-slate-800 rounded-lg p-5 hover:border-slate-700 transition-all text-xs space-y-3"
            >
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center space-x-3">
                  <span className="font-mono font-bold text-cyan-400">{anom.id}</span>
                  <span
                    className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                      anom.severity === 'CRITICAL'
                        ? 'bg-red-950 text-red-400 border-red-800'
                        : anom.severity === 'HIGH'
                        ? 'bg-orange-950 text-orange-400 border-orange-800'
                        : 'bg-amber-950 text-amber-400 border-amber-800'
                    }`}
                  >
                    {anom.severity}
                  </span>
                  <span className="text-sm font-bold text-white">{anom.anomaly_type}</span>
                </div>

                <div className="flex items-center space-x-2 font-mono text-[11px]">
                  <span className="text-slate-400">Session:</span>
                  <span className="text-cyan-300 font-bold">{anom.session_id}</span>
                  <span className="text-slate-400 text-[10px]">({anom.protocol})</span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                <div className="p-3 rounded bg-[#080c16] border border-slate-800/80">
                  <div className="text-[10px] uppercase font-bold text-slate-400">Observed Evidence</div>
                  <div className="font-mono text-amber-300 mt-1">{anom.evidence}</div>
                </div>
                <div className="p-3 rounded bg-[#080c16] border border-slate-800/80">
                  <div className="text-[10px] uppercase font-bold text-slate-400">Heuristic Diagnostic</div>
                  <div className="text-slate-300 mt-1 leading-relaxed">{anom.explanation}</div>
                </div>
              </div>

              <div className="flex justify-between items-center text-[10px] text-slate-400 pt-1 font-mono">
                <span>Anomaly Score: <strong className="text-red-400">{anom.anomaly_score}/100</strong> | Confidence: <strong className="text-emerald-400">{anom.confidence}</strong></span>
                <span>Captured Timestamp: {anom.timestamp}</span>
              </div>
            </div>
          ))
        ) : (
          <div className="p-12 text-center text-xs text-slate-400 bg-[#0d1424] border border-slate-800 rounded-lg">
            No protocol or TLS anomalies recorded matching the criteria.
          </div>
        )}
      </div>
    </div>
  );
};
