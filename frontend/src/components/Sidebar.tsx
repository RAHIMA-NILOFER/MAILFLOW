import React from 'react';
import {
  LayoutDashboard,
  FileCode2,
  Mail,
  Lock,
  Award,
  AlertTriangle,
  Brain,
  Target,
  ShieldCheck,
  FileText,
  Settings,
  ShieldAlert,
  Radio
} from 'lucide-react';
import { PCAPAnalysis } from '../types';

export type NavTab =
  | 'overview'
  | 'pcap_analyzer'
  | 'email_sessions'
  | 'tls_analysis'
  | 'certificates'
  | 'findings'
  | 'ai_risk'
  | 'anomalies'
  | 'threat_matrix'
  | 'security_posture'
  | 'reports'
  | 'settings';

interface SidebarProps {
  currentTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  analysis: PCAPAnalysis | null;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab, analysis }) => {
  const navItems = [
    { id: 'overview' as NavTab, label: 'Overview', icon: LayoutDashboard },
    { id: 'pcap_analyzer' as NavTab, label: 'PCAP Analyzer', icon: FileCode2, badge: 'Upload' },
    { id: 'email_sessions' as NavTab, label: 'Email Sessions', icon: Mail, count: analysis?.total_email_sessions },
    { id: 'tls_analysis' as NavTab, label: 'TLS Analysis', icon: Lock, count: analysis?.total_tls_sessions },
    { id: 'certificates' as NavTab, label: 'Certificates', icon: Award, count: analysis?.total_certificates },
    {
      id: 'findings' as NavTab,
      label: 'Cryptographic Findings',
      icon: AlertTriangle,
      badge: analysis?.critical_findings_count ? `${analysis.critical_findings_count} Critical` : undefined,
      badgeColor: 'bg-red-500/20 text-red-400 border border-red-500/40'
    },
    { id: 'ai_risk' as NavTab, label: 'AI Risk Analysis', icon: Brain, badge: 'AI Engine' },
    { id: 'anomalies' as NavTab, label: 'TLS Anomalies', icon: Radio, count: analysis?.anomalies?.length },
    { id: 'threat_matrix' as NavTab, label: 'Threat Prioritization', icon: Target },
    {
      id: 'security_posture' as NavTab,
      label: 'Security Posture',
      icon: ShieldCheck,
      badge: analysis?.security_score ? `${analysis.security_score}/100` : undefined,
      badgeColor: 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/40'
    },
    { id: 'reports' as NavTab, label: 'Reports', icon: FileText },
    { id: 'settings' as NavTab, label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="w-64 bg-[#0a0f1d] border-r border-[#1e293b] flex flex-col h-screen select-none shrink-0">
      {/* Brand Header */}
      <div className="p-4 border-b border-[#1e293b] flex items-center space-x-3">
        <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-600 via-blue-700 to-indigo-900 flex items-center justify-center shadow-lg shadow-cyan-950/40 border border-cyan-500/30">
          <ShieldAlert className="w-5 h-5 text-cyan-200" />
        </div>
        <div>
          <div className="font-bold text-sm tracking-wider text-slate-100 flex items-center gap-1.5">
            MAILFLOW <span className="text-cyan-400 font-extrabold">SENTINEL</span>
          </div>
          <div className="text-[10px] uppercase tracking-wider text-slate-400 font-medium">
            Forensic SOC Platform
          </div>
        </div>
      </div>

      {/* Navigation List */}
      <nav className="flex-1 overflow-y-auto px-2 py-3 space-y-1">
        <div className="px-3 py-1.5 text-[10px] font-bold text-slate-400 uppercase tracking-wider">
          Forensic Modules
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentTab === item.id;
          return (
            <button
              key={item.id}
              onClick={() => onSelectTab(item.id)}
              className={`w-full flex items-center justify-between px-3 py-2 rounded-md text-xs font-medium transition-all duration-150 group ${
                isActive
                  ? 'bg-cyan-950/60 text-cyan-300 border-l-2 border-cyan-400 pl-2.5 font-semibold shadow-inner'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
              }`}
            >
              <div className="flex items-center space-x-2.5 min-w-0">
                <Icon
                  className={`w-4 h-4 shrink-0 transition-colors ${
                    isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-slate-300'
                  }`}
                />
                <span className="truncate">{item.label}</span>
              </div>
              {item.badge && (
                <span
                  className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                    item.badgeColor || 'bg-slate-800 text-slate-400'
                  }`}
                >
                  {item.badge}
                </span>
              )}
              {item.count !== undefined && !item.badge && (
                <span className="text-[10px] text-slate-400 bg-slate-800/80 px-1.5 py-0.5 rounded font-mono">
                  {item.count}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Passive Mode Footprint Banner */}
      <div className="p-3 border-t border-[#1e293b] bg-[#070b14]/80">
        <div className="flex items-center space-x-2 text-[11px] text-emerald-400">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
          <span className="font-semibold tracking-wide">PASSIVE FORENSIC MODE</span>
        </div>
        <div className="text-[10px] text-slate-400 mt-1 leading-tight">
          Non-intrusive PCAP inspection. No traffic injection.
        </div>
      </div>
    </aside>
  );
};
