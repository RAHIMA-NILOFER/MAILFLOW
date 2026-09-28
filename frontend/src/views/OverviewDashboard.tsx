import React, { useState } from 'react';
import {
  FileCode,
  Mail,
  Lock,
  Award,
  AlertTriangle,
  ShieldCheck,
  Activity,
  ArrowUpRight,
  Filter,
  CheckCircle,
  AlertOctagon,
  Clock,
  Sparkles
} from 'lucide-react';
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Legend
} from 'recharts';
import { PCAPAnalysis, EmailSession } from '../types';

interface OverviewDashboardProps {
  analysis: PCAPAnalysis;
  onSelectSession: (session: EmailSession) => void;
  onNavigateTab: (tab: any) => void;
}

const COLORS_PROTO = ['#0284c7', '#3b82f6', '#8b5cf6'];
const COLORS_TLS = ['#10b981', '#06b6d4', '#f59e0b', '#ef4444', '#64748b'];
const COLORS_RISK = ['#ef4444', '#f97316', '#eab308', '#3b82f6', '#94a3b8'];

export const OverviewDashboard: React.FC<OverviewDashboardProps> = ({
  analysis,
  onSelectSession,
  onNavigateTab
}) => {
  const [timelineFilter, setTimelineFilter] = useState<string>('ALL');

  const protoData = [
    { name: 'SMTP', value: analysis.protocol_distribution.smtp },
    { name: 'IMAP', value: analysis.protocol_distribution.imap },
    { name: 'POP3', value: analysis.protocol_distribution.pop3 },
  ];

  const tlsData = [
    { name: 'TLS 1.3', value: analysis.tls_version_distribution.tls13 },
    { name: 'TLS 1.2', value: analysis.tls_version_distribution.tls12 },
    { name: 'TLS 1.1', value: analysis.tls_version_distribution.tls11 },
    { name: 'TLS 1.0', value: analysis.tls_version_distribution.tls10 },
    { name: 'SSL / Plaintext', value: analysis.tls_version_distribution.ssl_unknown },
  ];

  const riskData = [
    { name: 'Critical', value: analysis.risk_distribution.critical },
    { name: 'High', value: analysis.risk_distribution.high },
    { name: 'Medium', value: analysis.risk_distribution.medium },
    { name: 'Low', value: analysis.risk_distribution.low },
  ];

  const cryptoWeaknessData = [
    { name: 'Deprecated TLS', count: analysis.crypto_weakness_stats.deprecated_tls },
    { name: 'Weak Cipher', count: analysis.crypto_weakness_stats.weak_cipher },
    { name: 'Expired Cert', count: analysis.crypto_weakness_stats.cert_expired },
    { name: 'Cert Misconfig', count: analysis.crypto_weakness_stats.cert_misconfig },
    { name: 'Missing PFS', count: analysis.crypto_weakness_stats.missing_pfs },
    { name: 'Weak Key', count: analysis.crypto_weakness_stats.weak_key },
    { name: 'Insecure Sig Alg', count: analysis.crypto_weakness_stats.insecure_sig_alg },
    { name: 'Insecure STARTTLS', count: analysis.crypto_weakness_stats.insecure_starttls },
  ];

  const filteredTimeline = analysis.timeline.filter((evt) => {
    if (timelineFilter === 'ALL') return true;
    return evt.severity.toUpperCase() === timelineFilter.toUpperCase();
  });

  return (
    <div className="space-y-6 pb-12">
      {/* Demo Banner Notification if in Demo Mode */}
      {analysis.is_demo && (
        <div className="bg-gradient-to-r from-amber-950/40 via-amber-900/20 to-slate-900/40 border border-amber-500/30 rounded-lg p-3.5 flex items-center justify-between shadow-lg">
          <div className="flex items-center space-x-3">
            <div className="p-1.5 rounded bg-amber-500/20 text-amber-400">
              <Sparkles className="w-4 h-4" />
            </div>
            <div>
              <div className="text-xs font-bold text-amber-300 flex items-center gap-1.5">
                DEMO ANALYSIS ACTIVE &bull; ENTERPRISE EMAIL CAPTURE
              </div>
              <div className="text-[11px] text-slate-300">
                Displaying pre-loaded forensic PCAP capture with 127 email sessions, STARTTLS handshakes, and cryptographic findings.
              </div>
            </div>
          </div>
          <button
            onClick={() => onNavigateTab('pcap_analyzer')}
            className="text-xs font-semibold px-3 py-1.5 rounded bg-amber-500 hover:bg-amber-400 text-slate-950 shadow-md transition-colors"
          >
            Upload Real PCAP
          </button>
        </div>
      )}

      {/* Top 8 KPI Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 xl:grid-cols-8 gap-3">
        {[
          { label: 'Total Packets', value: analysis.total_packets.toLocaleString(), icon: FileCode, color: 'text-cyan-400' },
          { label: 'Email Sessions', value: analysis.total_email_sessions, icon: Mail, color: 'text-blue-400' },
          { label: 'TLS Sessions', value: analysis.total_tls_sessions, icon: Lock, color: 'text-emerald-400' },
          { label: 'STARTTLS', value: analysis.total_starttls_sessions, icon: Activity, color: 'text-indigo-400' },
          { label: 'Certificates', value: analysis.total_certificates, icon: Award, color: 'text-purple-400' },
          { label: 'Critical Findings', value: analysis.critical_findings_count, icon: AlertOctagon, color: 'text-red-400', isAlert: true },
          { label: 'High-Risk Sessions', value: analysis.high_findings_count, icon: AlertTriangle, color: 'text-orange-400' },
          { label: 'Posture Score', value: `${analysis.security_score}/100`, icon: ShieldCheck, color: 'text-cyan-300', isScore: true },
        ].map((kpi, idx) => {
          const Icon = kpi.icon;
          return (
            <div
              key={idx}
              className={`bg-[#0d1424] border ${
                kpi.isAlert && Number(kpi.value) > 0
                  ? 'border-red-900/60 bg-red-950/10'
                  : 'border-slate-800/80 hover:border-slate-700'
              } rounded-lg p-3 transition-all flex flex-col justify-between`}
            >
              <div className="flex items-center justify-between text-slate-400">
                <span className="text-[10px] font-bold uppercase tracking-wider">{kpi.label}</span>
                <Icon className={`w-3.5 h-3.5 ${kpi.color}`} />
              </div>
              <div className={`text-xl font-extrabold mt-2 font-mono ${kpi.color}`}>
                {kpi.value}
              </div>
            </div>
          );
        })}
      </div>

      {/* 4 Interactive Forensic Distribution Charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        {/* A. Protocol Distribution */}
        <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
          <div className="flex justify-between items-center mb-2">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Protocol Distribution
            </span>
            <span className="text-[10px] text-cyan-400 font-mono">127 Sessions</span>
          </div>
          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={protoData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={55}
                  innerRadius={30}
                  paddingAngle={4}
                >
                  {protoData.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS_PROTO[index % COLORS_PROTO.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', fontSize: '11px' }}
                />
                <Legend
                  wrapperStyle={{ fontSize: '10px', paddingTop: '6px' }}
                  iconSize={8}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* B. TLS Version Distribution */}
        <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
          <div className="flex justify-between items-center mb-2">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
              TLS Version Distribution
            </span>
            <span className="text-[10px] text-emerald-400 font-mono">RFC 8996 Audit</span>
          </div>
          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={tlsData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={55}
                  innerRadius={30}
                  paddingAngle={3}
                >
                  {tlsData.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS_TLS[index % COLORS_TLS.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', fontSize: '11px' }}
                />
                <Legend
                  wrapperStyle={{ fontSize: '10px', paddingTop: '6px' }}
                  iconSize={8}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* C. Risk Distribution */}
        <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
          <div className="flex justify-between items-center mb-2">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Risk Level Breakdown
            </span>
            <span className="text-[10px] text-red-400 font-mono">AI Risk Graded</span>
          </div>
          <div className="h-44 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={riskData}
                  dataKey="value"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={55}
                  innerRadius={30}
                  paddingAngle={3}
                >
                  {riskData.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={COLORS_RISK[index % COLORS_RISK.length]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', fontSize: '11px' }}
                />
                <Legend
                  wrapperStyle={{ fontSize: '10px', paddingTop: '6px' }}
                  iconSize={8}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* D. Security Posture Summary Card */}
        <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-4 flex flex-col justify-between">
          <div className="flex justify-between items-center mb-2">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
              Security Posture Score
            </span>
            <span className="text-[10px] text-cyan-400 font-mono">NIST SP 800-52</span>
          </div>
          <div className="flex flex-col items-center justify-center my-auto">
            <div className="relative w-24 h-24 flex items-center justify-center">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 36 36">
                <path
                  className="text-slate-800"
                  strokeWidth="3.5"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
                <path
                  className="text-cyan-400"
                  strokeDasharray={`${analysis.security_score}, 100`}
                  strokeWidth="3.5"
                  strokeLinecap="round"
                  stroke="currentColor"
                  fill="none"
                  d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"
                />
              </svg>
              <div className="absolute text-center">
                <span className="text-xl font-extrabold font-mono text-white">{analysis.security_score}</span>
                <span className="text-[9px] text-slate-400 block -mt-1">/100</span>
              </div>
            </div>
            <div className="text-xs font-semibold text-slate-200 mt-2">
              Status: <span className="text-amber-400 font-bold">{analysis.risk_assessment?.posture_rating || 'Moderate'}</span>
            </div>
          </div>
          <button
            onClick={() => onNavigateTab('security_posture')}
            className="w-full py-1 text-[11px] font-semibold text-cyan-400 hover:text-cyan-300 hover:bg-cyan-950/40 rounded transition-colors text-center mt-2 border border-cyan-900/40"
          >
            Inspect Posture Breakdown &rarr;
          </button>
        </div>
      </div>

      {/* Cryptographic Weaknesses Bar Chart */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5">
        <div className="flex justify-between items-center mb-4">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-slate-200">
              Cryptographic Weaknesses Detected
            </div>
            <div className="text-[11px] text-slate-400">
              Passive detection across TLS handshakes, cipher negotiation, certificate chains, and STARTTLS policies
            </div>
          </div>
          <button
            onClick={() => onNavigateTab('findings')}
            className="text-xs font-semibold text-cyan-400 hover:underline flex items-center gap-1"
          >
            View All Findings <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
        <div className="h-56 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={cryptoWeaknessData} margin={{ top: 10, right: 10, left: -20, bottom: 20 }}>
              <XAxis
                dataKey="name"
                stroke="#64748b"
                fontSize={10}
                interval={0}
                angle={-15}
                textAnchor="end"
              />
              <YAxis stroke="#64748b" fontSize={10} />
              <Tooltip
                contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', fontSize: '11px' }}
                cursor={{ fill: '#1e293b55' }}
              />
              <Bar dataKey="count" fill="#0284c7" radius={[4, 4, 0, 0]}>
                {cryptoWeaknessData.map((entry, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={entry.count > 0 ? (index < 3 ? '#ef4444' : '#f97316') : '#334155'}
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Chronological Timeline of Suspicious Events */}
      <div className="bg-[#0d1424] border border-slate-800 rounded-lg p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4 pb-3 border-b border-slate-800">
          <div>
            <div className="text-xs font-bold uppercase tracking-wider text-slate-200 flex items-center gap-2">
              <Clock className="w-4 h-4 text-cyan-400" />
              Chronological Suspicious TLS & Email Events
            </div>
            <div className="text-[11px] text-slate-400 mt-0.5">
              Sequence of anomalous handshakes, weak cipher negotiations, and downgrade events captured in PCAP
            </div>
          </div>
          <div className="flex items-center space-x-1.5">
            <Filter className="w-3.5 h-3.5 text-slate-400 mr-1" />
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map((sev) => (
              <button
                key={sev}
                onClick={() => setTimelineFilter(sev)}
                className={`text-[10px] font-bold px-2 py-1 rounded transition-colors ${
                  timelineFilter === sev
                    ? 'bg-cyan-600 text-white'
                    : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        <div className="space-y-3">
          {filteredTimeline.length > 0 ? (
            filteredTimeline.map((evt) => {
              const sevBadge = {
                critical: 'bg-red-950/80 text-red-400 border-red-800/60',
                high: 'bg-orange-950/80 text-orange-400 border-orange-800/60',
                medium: 'bg-amber-950/80 text-amber-400 border-amber-800/60',
                low: 'bg-blue-950/80 text-blue-400 border-blue-800/60',
              }[evt.severity.toLowerCase()] || 'bg-slate-800 text-slate-400';

              const sessionObj = analysis.sessions.find((s) => s.session_id === evt.session_id);

              return (
                <div
                  key={evt.id}
                  className="p-3.5 rounded-lg bg-[#090e1a] border border-slate-800/80 hover:border-slate-700 transition-all flex flex-col md:flex-row md:items-center justify-between gap-3"
                >
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${sevBadge}`}>
                        {evt.severity}
                      </span>
                      <span className="font-mono text-xs font-semibold text-cyan-300">
                        {evt.session_id}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 font-mono">
                        {evt.protocol}
                      </span>
                      <span className="text-[10px] text-slate-400 font-mono">{evt.timestamp}</span>
                    </div>
                    <div className="text-xs font-bold text-slate-100">{evt.title}</div>
                    <div className="text-[11px] text-slate-400 max-w-3xl leading-relaxed">
                      {evt.description}
                    </div>
                    <div className="text-[10px] text-slate-400 font-mono">
                      Source: <span className="text-slate-300">{evt.source_ip}</span> &rarr; Dest:{' '}
                      <span className="text-slate-300">{evt.dest_ip}</span>
                    </div>
                  </div>

                  {sessionObj && (
                    <button
                      onClick={() => onSelectSession(sessionObj)}
                      className="shrink-0 text-xs px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-cyan-400 hover:text-cyan-300 border border-slate-700 font-medium transition-colors"
                    >
                      Inspect Stream &rarr;
                    </button>
                  )}
                </div>
              );
            })
          ) : (
            <div className="p-8 text-center text-xs text-slate-400">
              No timeline events match the selected severity filter.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
