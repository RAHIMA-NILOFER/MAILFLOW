import React, { useState } from 'react';
import {
  Target,
  ShieldAlert,
  AlertTriangle,
  ArrowUpRight,
  CheckCircle2,
  AlertOctagon,
  Filter,
  Layers,
  ChevronRight
} from 'lucide-react';
import { PCAPAnalysis, ThreatMatrixItem } from '../types';

interface ThreatPrioritizationProps {
  analysis: PCAPAnalysis;
  onNavigateTab: (tab: any) => void;
}

export const ThreatPrioritization: React.FC<ThreatPrioritizationProps> = ({
  analysis,
  onNavigateTab
}) => {
  const [selectedThreat, setSelectedThreat] = useState<ThreatMatrixItem | null>(
    analysis.threat_matrix[0] || null
  );

  const threats = analysis.threat_matrix || [];

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner Header */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-cyan-950 text-cyan-300 text-[11px] font-semibold mb-2 border border-cyan-800/40">
              <Target className="w-3.5 h-3.5 text-cyan-400" />
              Automated Forensic Risk Prioritization
            </div>
            <h2 className="text-xl font-bold text-white">Threat Prioritization & Impact Matrix</h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Dynamically maps cryptographic findings onto a 2D Impact vs Likelihood / Exploitability risk matrix to prioritize incident response and remediation efforts.
            </p>
          </div>
        </div>
      </div>

      {/* Main 2D Matrix and Threat Detail Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: 2D Interactive Matrix Grid */}
        <div className="lg:col-span-7 bg-[#0d1424] border border-slate-800 rounded-lg p-6 flex flex-col justify-between">
          <div className="flex justify-between items-center mb-4 pb-2 border-b border-slate-800">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Interactive 2D Threat Matrix (Impact vs Likelihood)
            </div>
            <span className="text-[10px] text-cyan-400 font-mono">Click any bubble node to inspect</span>
          </div>

          {/* Matrix Canvas Container */}
          <div className="relative w-full aspect-square max-w-[420px] mx-auto bg-[#080c16] border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
            {/* Quadrant Background Colors */}
            <div className="absolute inset-4 grid grid-cols-2 grid-rows-2 pointer-events-none opacity-20">
              <div className="bg-amber-500/20 border-r border-b border-slate-700"></div>
              <div className="bg-red-500/30 border-b border-slate-700"></div>
              <div className="bg-blue-500/20 border-r border-slate-700"></div>
              <div className="bg-orange-500/20"></div>
            </div>

            {/* Y Axis Label */}
            <div className="absolute -left-6 top-1/2 -translate-y-1/2 -rotate-90 text-[10px] uppercase font-bold text-slate-400 tracking-widest">
              Impact (Severity) &rarr;
            </div>

            {/* Placed Nodes */}
            <div className="relative w-full h-full">
              {threats.map((threat, idx) => {
                const isSelected = selectedThreat?.finding_id === threat.finding_id;
                // Calculate position: Likelihood 1-5 (X axis 10% to 90%), Impact 1-5 (Y axis 90% to 10%)
                const left = `${((threat.likelihood_score - 1) / 4) * 80 + 10}%`;
                const top = `${(1 - (threat.impact_score - 1) / 4) * 80 + 10}%`;

                const bgNodeMap: Record<string, string> = {
                  CRITICAL: 'bg-red-500 text-white ring-red-400',
                  HIGH: 'bg-orange-500 text-white ring-orange-400',
                  MEDIUM: 'bg-amber-500 text-slate-950 ring-amber-400',
                  LOW: 'bg-blue-500 text-white ring-blue-400',
                  INFO: 'bg-slate-700 text-white ring-slate-500',
                };
                const bgNode = bgNodeMap[threat.severity] || 'bg-slate-700 text-white ring-slate-500';

                return (
                  <button
                    key={idx}
                    onClick={() => setSelectedThreat(threat)}
                    style={{ left, top }}
                    className={`absolute -translate-x-1/2 -translate-y-1/2 w-8 h-8 rounded-full flex items-center justify-center font-mono font-bold text-[10px] shadow-lg transition-all transform hover:scale-125 z-20 ${bgNode} ${
                      isSelected ? 'ring-4 ring-cyan-400 scale-125 shadow-cyan-900/80 z-30' : ''
                    }`}
                    title={`${threat.finding_id}: ${threat.title}`}
                  >
                    {threat.finding_id.replace('CRYPTO-', '')}
                  </button>
                );
              })}
            </div>

            {/* X Axis Label */}
            <div className="text-center text-[10px] uppercase font-bold text-slate-400 tracking-widest pt-2">
              Likelihood / Exploitability &rarr;
            </div>
          </div>

          <div className="flex items-center justify-around text-[10px] text-slate-400 pt-4 border-t border-slate-800 font-mono mt-4">
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-red-500"></span> Critical Priority</span>
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-orange-500"></span> High Priority</span>
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span> Medium Priority</span>
            <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-blue-500"></span> Low Priority</span>
          </div>
        </div>

        {/* Right Column: Selected Threat Details & Remediation Prioritization */}
        <div className="lg:col-span-5 space-y-4">
          {selectedThreat ? (
            <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5 space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                <span className="font-mono text-sm font-bold text-cyan-400">
                  {selectedThreat.finding_id}
                </span>
                <span
                  className={`text-[10px] font-bold px-2 py-0.5 rounded border ${
                    selectedThreat.severity === 'CRITICAL'
                      ? 'bg-red-950 text-red-400 border-red-800'
                      : selectedThreat.severity === 'HIGH'
                      ? 'bg-orange-950 text-orange-400 border-orange-800'
                      : 'bg-amber-950 text-amber-400 border-amber-800'
                  }`}
                >
                  {selectedThreat.severity} THREAT
                </span>
              </div>

              <div>
                <h3 className="text-sm font-bold text-white">{selectedThreat.title}</h3>
              </div>

              <div className="grid grid-cols-2 gap-2 text-xs">
                <div className="p-2.5 rounded bg-[#080c16] border border-slate-800">
                  <div className="text-[10px] uppercase font-bold text-slate-400">Impact Score</div>
                  <div className="font-mono font-bold text-red-400 text-base mt-0.5">
                    {selectedThreat.impact_score} / 5
                  </div>
                </div>
                <div className="p-2.5 rounded bg-[#080c16] border border-slate-800">
                  <div className="text-[10px] uppercase font-bold text-slate-400">Likelihood Score</div>
                  <div className="font-mono font-bold text-orange-400 text-base mt-0.5">
                    {selectedThreat.likelihood_score} / 5
                  </div>
                </div>
                <div className="p-2.5 rounded bg-[#080c16] border border-slate-800">
                  <div className="text-[10px] uppercase font-bold text-slate-400">Exploitability</div>
                  <div className="font-mono font-bold text-cyan-300 text-sm mt-0.5">
                    {selectedThreat.exploitability}
                  </div>
                </div>
                <div className="p-2.5 rounded bg-[#080c16] border border-slate-800">
                  <div className="text-[10px] uppercase font-bold text-slate-400">Exposure Scope</div>
                  <div className="font-mono font-bold text-slate-200 text-sm mt-0.5">
                    {selectedThreat.exposure}
                  </div>
                </div>
              </div>

              <div className="p-3 rounded bg-slate-900/80 border border-slate-800 text-xs flex justify-between items-center font-mono">
                <span className="text-slate-400">Affected Email Sessions:</span>
                <span className="text-cyan-300 font-bold">{selectedThreat.affected_sessions_count} sessions</span>
              </div>

              <button
                onClick={() => onNavigateTab('findings')}
                className="w-full py-2 bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 rounded text-xs font-semibold border border-slate-700 transition-colors flex items-center justify-center gap-1"
              >
                <span>Inspect in Findings Management</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          ) : (
            <div className="p-12 text-center text-xs text-slate-400 bg-[#0d1424] border border-slate-800 rounded-lg">
              Click a bubble on the matrix to view prioritized threat details.
            </div>
          )}

          {/* Actionable Threat Priority Backlog */}
          <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5">
            <div className="text-xs font-bold uppercase tracking-wider text-slate-200 mb-3 pb-2 border-b border-slate-800">
              Prioritized Remediation Queue
            </div>
            <div className="space-y-2">
              {threats.slice(0, 4).map((t, i) => (
                <div
                  key={t.finding_id}
                  onClick={() => setSelectedThreat(t)}
                  className="p-2.5 rounded bg-[#080c16] border border-slate-800 hover:border-slate-700 cursor-pointer flex items-center justify-between text-xs transition-colors"
                >
                  <div className="flex items-center space-x-2">
                    <span className="w-5 h-5 rounded bg-slate-800 font-mono text-[10px] font-bold flex items-center justify-center text-slate-300">
                      {i + 1}
                    </span>
                    <span className="font-mono text-cyan-300">{t.finding_id}</span>
                    <span className="font-medium text-slate-200 truncate max-w-[160px]">{t.title}</span>
                  </div>
                  <span
                    className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${
                      t.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border-red-800' : 'bg-orange-950 text-orange-400 border-orange-800'
                    }`}
                  >
                    {t.severity}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
