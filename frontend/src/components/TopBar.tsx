import React, { useState } from 'react';
import {
  Bell,
  FileCode,
  Shield,
  Clock,
  CheckCircle2,
  AlertOctagon,
  User,
  Upload,
  RefreshCw,
  Sparkles
} from 'lucide-react';
import { PCAPAnalysis } from '../types';

interface TopBarProps {
  analysis: PCAPAnalysis | null;
  onOpenUpload: () => void;
  onLoadDemo: () => void;
  isLoading: boolean;
}

export const TopBar: React.FC<TopBarProps> = ({
  analysis,
  onOpenUpload,
  onLoadDemo,
  isLoading
}) => {
  const [showNotifications, setShowNotifications] = useState(false);

  return (
    <header className="h-14 bg-[#0a0f1d] border-b border-[#1e293b] flex items-center justify-between px-6 shrink-0 z-20">
      {/* Left: Active Analysis Metadata */}
      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2">
          <FileCode className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-semibold text-slate-300">File:</span>
          <span className="text-xs font-mono text-cyan-300 bg-cyan-950/40 px-2 py-0.5 rounded border border-cyan-800/40">
            {analysis?.filename || 'No PCAP loaded'}
          </span>
        </div>

        {/* Demo Analysis or Live Forensic Badge */}
        {analysis?.is_demo ? (
          <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-amber-500/10 text-amber-400 border border-amber-500/30 flex items-center gap-1">
            <Sparkles className="w-3 h-3" /> DEMO ANALYSIS
          </span>
        ) : (
          <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3" /> LIVE PCAP AUDIT
          </span>
        )}

        <div className="hidden lg:flex items-center space-x-2 text-slate-400 text-xs">
          <Clock className="w-3.5 h-3.5 text-slate-400" />
          <span>{analysis?.upload_timestamp || 'N/A'}</span>
        </div>
      </div>

      {/* Right: Actions, Notifications & Profile */}
      <div className="flex items-center space-x-3">
        {/* Quick Demo Switch */}
        <button
          onClick={onLoadDemo}
          title="Reload Demo Dataset"
          className="text-xs px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 flex items-center gap-1.5 transition-colors"
        >
          <RefreshCw className={`w-3 h-3 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          <span className="hidden sm:inline">Reset Demo</span>
        </button>

        {/* Upload PCAP Button */}
        <button
          onClick={onOpenUpload}
          className="text-xs px-3 py-1 rounded bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium shadow-sm shadow-cyan-900/30 flex items-center gap-1.5 transition-all"
        >
          <Upload className="w-3.5 h-3.5" />
          <span>Upload PCAP</span>
        </button>

        {/* Notifications */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="p-1.5 rounded-md text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors relative"
            title="Forensic Alerts"
          >
            <Bell className="w-4 h-4" />
            {analysis?.critical_findings_count ? (
              <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-red-500 ring-2 ring-[#0a0f1d]"></span>
            ) : null}
          </button>

          {showNotifications && (
            <div className="absolute right-0 mt-2 w-80 bg-[#0f172a] border border-[#1e293b] rounded-lg shadow-2xl p-3 z-50 text-xs">
              <div className="font-semibold text-slate-200 pb-2 border-b border-slate-800 flex justify-between items-center">
                <span>Cryptographic Alerts</span>
                <span className="text-[10px] bg-red-950 text-red-400 px-1.5 py-0.2 rounded font-mono">
                  {analysis?.critical_findings_count || 0} Critical
                </span>
              </div>
              <div className="space-y-2 mt-2 max-h-60 overflow-y-auto">
                {analysis?.timeline?.slice(0, 4).map((evt) => (
                  <div
                    key={evt.id}
                    className="p-2 rounded bg-slate-900/80 border border-slate-800 hover:border-slate-700"
                  >
                    <div className="flex items-center gap-1.5 text-red-400 font-semibold text-[11px]">
                      <AlertOctagon className="w-3 h-3 shrink-0" />
                      <span className="truncate">{evt.title}</span>
                    </div>
                    <div className="text-slate-400 text-[10px] mt-1 leading-snug line-clamp-2">
                      {evt.description}
                    </div>
                    <div className="text-[9px] text-slate-400 mt-1 font-mono">
                      {evt.timestamp}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* User Profile Info */}
        <div className="flex items-center space-x-2 pl-2 border-l border-slate-800">
          <div className="w-7 h-7 rounded-full bg-cyan-950 border border-cyan-700/50 flex items-center justify-center text-cyan-300 text-xs font-bold">
            SOC
          </div>
          <div className="hidden md:block text-left">
            <div className="text-xs font-medium text-slate-200 leading-none">Forensic Analyst</div>
            <div className="text-[10px] text-slate-400 leading-tight">SOC Node #01</div>
          </div>
        </div>
      </div>
    </header>
  );
};
