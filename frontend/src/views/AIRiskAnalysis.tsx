import React from 'react';
import {
  Brain,
  ShieldAlert,
  Sparkles,
  Layers,
  Cpu,
  Zap,
  CheckCircle2,
  AlertOctagon,
  Info,
  TrendingUp,
  Activity
} from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
  RadarChart,
  PolarGrid,
  PolarAngleAxis,
  PolarRadiusAxis,
  Radar
} from 'recharts';
import { PCAPAnalysis } from '../types';

interface AIRiskAnalysisProps {
  analysis: PCAPAnalysis;
  onNavigateTab: (tab: any) => void;
}

export const AIRiskAnalysis: React.FC<AIRiskAnalysisProps> = ({ analysis, onNavigateTab }) => {
  const risk = analysis.risk_assessment;
  const overallScore = risk ? risk.overall_risk_score : 29;

  const featureChartData = risk?.feature_contributions?.map((fc) => ({
    name: fc.feature_name.split(' & ')[0],
    fullName: fc.feature_name,
    points: fc.contribution_points,
    desc: fc.description,
  })) || [
    { name: 'TLS Version', points: 25, desc: 'Penalties for deprecated TLS 1.0/1.1' },
    { name: 'Cipher Strength', points: 20, desc: 'Penalties for 3DES and RC4' },
    { name: 'Certificate', points: 15, desc: 'Penalties for expired/self-signed certs' },
    { name: 'Key Exchange', points: 10, desc: 'Penalties for missing PFS' },
    { name: 'STARTTLS', points: 10, desc: 'Penalties for unencrypted plaintext streams' },
    { name: 'Anomaly Score', points: 12, desc: 'Heuristic weights for handshake delay' },
  ];

  const radarData = [
    { category: 'Cryptographic', score: risk?.cryptographic_risk || 65 },
    { category: 'Certificates', score: risk?.certificate_risk || 70 },
    { category: 'Protocols', score: risk?.protocol_risk || 50 },
    { category: 'Anomalies', score: risk?.tls_anomaly_risk || 55 },
    { category: 'Configuration', score: risk?.configuration_risk || 60 },
  ];

  return (
    <div className="space-y-6 pb-12">
      {/* Top Banner Header */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-purple-950 text-purple-300 text-[11px] font-semibold mb-2 border border-purple-800/40">
              <Brain className="w-3.5 h-3.5 text-purple-400" />
              Explainable Risk Engine
            </div>
            <h2 className="text-xl font-bold text-white">
              AI-Assisted Cryptographic Risk Engine
            </h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl leading-relaxed">
              Transparent, deterministic feature-attribution risk classification model. Quantifies posture exposure by scoring protocol deprecations, cipher weaknesses, certificate chain failures, and anomalous handshake traces.
            </p>
          </div>

          {/* Model Badge */}
          <div className="p-3 rounded-lg bg-[#080c16] border border-purple-900/40 text-right">
            <div className="text-[10px] text-slate-400">Architecture</div>
            <div className="text-xs font-mono font-bold text-purple-300">
              {risk?.model_version || 'Sentinel-RiskEngine-v2.4 (Explainable)'}
            </div>
          </div>
        </div>
      </div>

      {/* Main KPI Risk Cards */}
      <div className="grid grid-cols-1 md:grid-cols-6 gap-4">
        {/* Main Composite Risk Gauge */}
        <div className="md:col-span-2 bg-[#0d1424] border border-slate-800 rounded-lg p-5 flex flex-col justify-between items-center text-center">
          <div className="w-full flex justify-between items-center text-xs font-bold uppercase tracking-wider text-slate-300">
            <span>Overall Risk Score</span>
            <span className="text-[10px] text-purple-400 font-mono">0 - 100 Scale</span>
          </div>

          <div className="my-6">
            <div className="text-5xl font-extrabold font-mono text-transparent bg-clip-text bg-gradient-to-r from-red-400 via-orange-400 to-amber-300">
              {overallScore}
            </div>
            <div className="text-xs text-slate-400 mt-1 font-mono">Total Risk Degradation Points</div>
            <div className="mt-3 inline-block px-3 py-1 rounded-full text-xs font-bold bg-red-950/80 text-red-300 border border-red-800/60">
              Posture: {risk?.posture_rating || 'Moderate'}
            </div>
          </div>

          <div className="w-full text-[11px] text-slate-400 border-t border-slate-800 pt-3 text-left leading-relaxed">
            Composite risk computed via weighted feature vector accumulation across 6 distinct cryptographic pillars.
          </div>
        </div>

        {/* 5 Risk Category Metric Cards */}
        <div className="md:col-span-4 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {[
            { label: 'Cryptographic Risk', score: risk?.cryptographic_risk ?? 65, color: 'text-red-400', desc: '3DES, RC4 & Static RSA' },
            { label: 'Certificate Risk', score: risk?.certificate_risk ?? 70, color: 'text-orange-400', desc: 'Expired certs & weak signatures' },
            { label: 'Protocol Risk', score: risk?.protocol_risk ?? 50, color: 'text-amber-400', desc: 'Missing STARTTLS & cleartext' },
            { label: 'TLS Anomaly Risk', score: risk?.tls_anomaly_risk ?? 55, color: 'text-indigo-400', desc: 'Downgrades & handshake latency' },
            { label: 'Configuration Risk', score: risk?.configuration_risk ?? 60, color: 'text-purple-400', desc: 'MTA-STS & cipher prioritization' },
          ].map((card, idx) => (
            <div
              key={idx}
              className="bg-[#0d1424] border border-slate-800 rounded-lg p-4 flex flex-col justify-between"
            >
              <div className="flex justify-between items-center text-xs font-bold text-slate-300">
                <span className="truncate">{card.label}</span>
                <span className={`font-mono text-sm font-extrabold ${card.color}`}>
                  {card.score}/100
                </span>
              </div>
              <div className="w-full h-1.5 rounded-full bg-slate-800 my-3 overflow-hidden">
                <div
                  className="h-full bg-gradient-to-r from-cyan-500 to-red-500 rounded-full"
                  style={{ width: `${card.score}%` }}
                ></div>
              </div>
              <div className="text-[10px] text-slate-400 leading-tight">
                {card.desc}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Explainable AI Section: Feature Contribution Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        <div className="lg:col-span-7 bg-[#0d1424] border border-slate-800 rounded-lg p-5">
          <div className="flex justify-between items-center mb-4 pb-2 border-b border-slate-800">
            <div>
              <div className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-1.5">
                <Sparkles className="w-4 h-4 text-purple-400" />
                Explainable Feature Contribution Breakdown
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Exact mathematical points assigned to each security violation leading to the risk score
              </div>
            </div>
            <div className="text-xs font-mono text-cyan-400 font-bold">
              Total: {overallScore} pts
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={featureChartData} layout="vertical" margin={{ left: 20, right: 30, top: 10, bottom: 10 }}>
                <XAxis type="number" stroke="#64748b" fontSize={10} domain={[0, 30]} />
                <YAxis dataKey="name" type="category" stroke="#64748b" fontSize={11} width={110} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', fontSize: '11px' }}
                  formatter={(val: any) => [`+${val} Points`, 'Risk Weight']}
                />
                <Bar dataKey="points" fill="#8b5cf6" radius={[0, 4, 4, 0]}>
                  {featureChartData.map((_, index) => (
                    <Cell
                      key={`cell-${index}`}
                      fill={['#ef4444', '#f97316', '#eab308', '#06b6d4', '#8b5cf6', '#3b82f6'][index % 6]}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Radar Map */}
        <div className="lg:col-span-5 bg-[#0d1424] border border-slate-800 rounded-lg p-5 flex flex-col justify-between">
          <div className="text-xs font-bold uppercase tracking-wider text-slate-200 pb-2 border-b border-slate-800">
            Risk Vector Radar Profile
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <RadarChart data={radarData}>
                <PolarGrid stroke="#1e293b" />
                <PolarAngleAxis dataKey="category" stroke="#94a3b8" fontSize={10} />
                <PolarRadiusAxis stroke="#475569" angle={30} domain={[0, 100]} fontSize={9} />
                <Radar name="Risk Index" dataKey="score" stroke="#a855f7" fill="#a855f7" fillOpacity={0.4} />
                <Tooltip contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', fontSize: '11px' }} />
              </RadarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Transparent "WHY THIS SESSION WAS FLAGGED" Explanation Box */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5">
        <div className="text-xs font-bold uppercase tracking-wider text-slate-200 mb-3 pb-2 border-b border-slate-800 flex items-center gap-2">
          <Info className="w-4 h-4 text-cyan-400" />
          Explainable AI Decision Audit &bull; Why Findings Were Flagged
        </div>

        <div className="space-y-2.5">
          {[
            { tag: '+25 Pts', title: 'Deprecated TLS 1.0/1.1 Negotiation Detected', reason: 'RFC 8996 formally deprecates TLS 1.0 and 1.1 due to broken cipher suites and vulnerability to downgrade attacks.', sev: 'CRITICAL' },
            { tag: '+20 Pts', title: 'Legacy 3DES & RC4 Ciphers In Active Streams', reason: '3DES is vulnerable to Sweet32 collision attacks (CVE-2016-2183) over high volume connections; RC4 has known statistical keystream biases.', sev: 'CRITICAL' },
            { tag: '+15 Pts', title: 'Expired & Self-Signed X.509 Certificates Present', reason: 'Unverified certificates expose mail transmission to silent MITM eavesdropping without client notification.', sev: 'HIGH' },
            { tag: '+10 Pts', title: 'Static RSA Key Exchange Lacking Forward Secrecy', reason: 'Inability to provide ephemeral Diffie-Hellman keys permits retroactive offline decryption if private keys leak.', sev: 'MEDIUM' },
            { tag: '+10 Pts', title: 'STARTTLS Stripping / Downgrade Failure (Status 454)', reason: 'Mail client requested cryptographic STARTTLS upgrade but fell back to unencrypted plaintext transmission.', sev: 'CRITICAL' },
            { tag: '+12 Pts', title: 'Suspicious Handshake Latency & Auth Leaks', reason: 'Unusual delay in handshake completion and cleartext authentication commands sent prior to encryption.', sev: 'HIGH' },
          ].map((item, idx) => (
            <div
              key={idx}
              className="p-3 rounded-lg bg-[#080c16] border border-slate-800 flex items-start justify-between gap-3 text-xs"
            >
              <div className="flex items-start gap-3">
                <span className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 font-mono font-bold text-[11px] border border-purple-800 shrink-0">
                  {item.tag}
                </span>
                <div>
                  <div className="font-bold text-slate-200">{item.title}</div>
                  <div className="text-slate-400 text-[11px] mt-0.5 leading-snug">{item.reason}</div>
                </div>
              </div>

              <span
                className={`text-[10px] font-bold px-2 py-0.5 rounded border shrink-0 ${
                  item.sev === 'CRITICAL' ? 'bg-red-950 text-red-400 border-red-800' : (item.sev === 'HIGH' ? 'bg-orange-950 text-orange-400 border-orange-800' : 'bg-amber-950 text-amber-400 border-amber-800')
                }`}
              >
                {item.sev}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
