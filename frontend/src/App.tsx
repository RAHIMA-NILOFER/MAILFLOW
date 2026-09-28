import React, { useState, useEffect } from 'react';
import { Sidebar, NavTab } from './components/Sidebar';
import { TopBar } from './components/TopBar';
import { LandingPage } from './components/LandingPage';
import { OverviewDashboard } from './views/OverviewDashboard';
import { PCAPAnalyzer } from './views/PCAPAnalyzer';
import { EmailSessions } from './views/EmailSessions';
import { SessionDetail } from './views/SessionDetail';
import { TLSAnalysis } from './views/TLSAnalysis';
import { Certificates } from './views/Certificates';
import { CryptographicFindings } from './views/CryptographicFindings';
import { AIRiskAnalysis } from './views/AIRiskAnalysis';
import { TLSAnomalyDetection } from './views/TLSAnomalyDetection';
import { ThreatPrioritization } from './views/ThreatPrioritization';
import { SecurityPosture } from './views/SecurityPosture';
import { Reports } from './views/Reports';
import { Settings } from './views/Settings';
import { PCAPAnalysis, EmailSession } from './types';
import { fetchAnalysis, getOfflineDemoAnalysis } from './services/api';

export function App() {
  const [inApp, setInApp] = useState(false);
  const [currentTab, setCurrentTab] = useState<NavTab>('overview');
  const [analysis, setAnalysis] = useState<PCAPAnalysis | null>(null);
  const [selectedSession, setSelectedSession] = useState<EmailSession | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  useEffect(() => {
    loadAnalysisData('demo');
  }, []);

  const loadAnalysisData = async (id: string = 'demo') => {
    setIsLoading(true);
    try {
      const data = await fetchAnalysis(id);
      setAnalysis(data);
    } catch (err) {
      console.warn('Failed to fetch from backend, loading fallback demo', err);
      setAnalysis(getOfflineDemoAnalysis());
    } finally {
      setIsLoading(false);
    }
  };

  const handleSelectSession = (session: EmailSession) => {
    setSelectedSession(session);
  };

  const handleBackToSessions = () => {
    setSelectedSession(null);
  };

  const handleNavigateTab = (tab: NavTab) => {
    setSelectedSession(null);
    setCurrentTab(tab);
  };

  // If user hasn't clicked "Enter Demo" or "Sign In", display LandingPage
  if (!inApp) {
    return (
      <LandingPage
        onEnterDemo={() => {
          setInApp(true);
          setCurrentTab('overview');
        }}
        onEnterLogin={() => {
          setInApp(true);
          setCurrentTab('overview');
        }}
      />
    );
  }

  return (
    <div className="flex h-screen bg-[#070a12] text-slate-100 overflow-hidden font-sans select-none">
      {/* Sidebar Navigation */}
      <Sidebar
        currentTab={currentTab}
        onSelectTab={(tab) => {
          setSelectedSession(null);
          setCurrentTab(tab);
        }}
        analysis={analysis}
      />

      {/* Main App Content Area */}
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        {/* Top Header Bar */}
        <TopBar
          analysis={analysis}
          onOpenUpload={() => {
            setSelectedSession(null);
            setCurrentTab('pcap_analyzer');
          }}
          onLoadDemo={() => loadAnalysisData('demo')}
          isLoading={isLoading}
        />

        {/* Dynamic Page Views */}
        <main className="flex-1 overflow-y-auto p-6 bg-[#070a12]">
          {analysis ? (
            selectedSession ? (
              <SessionDetail
                session={selectedSession}
                analysis={analysis}
                onBack={handleBackToSessions}
                onNavigateTab={handleNavigateTab}
              />
            ) : (
              <>
                {currentTab === 'overview' && (
                  <OverviewDashboard
                    analysis={analysis}
                    onSelectSession={handleSelectSession}
                    onNavigateTab={handleNavigateTab}
                  />
                )}
                {currentTab === 'pcap_analyzer' && (
                  <PCAPAnalyzer
                    currentAnalysis={analysis}
                    onAnalysisLoaded={(newAnalysis) => {
                      setAnalysis(newAnalysis);
                      setCurrentTab('overview');
                    }}
                    onLoadDemo={() => loadAnalysisData('demo')}
                    onNavigateTab={handleNavigateTab}
                  />
                )}
                {currentTab === 'email_sessions' && (
                  <EmailSessions
                    analysis={analysis}
                    onSelectSession={handleSelectSession}
                  />
                )}
                {currentTab === 'tls_analysis' && (
                  <TLSAnalysis
                    analysis={analysis}
                    onNavigateSession={(sessionId) => {
                      const sess = analysis.sessions.find(s => s.session_id === sessionId);
                      if (sess) handleSelectSession(sess);
                    }}
                  />
                )}
                {currentTab === 'certificates' && (
                  <Certificates
                    analysis={analysis}
                    onNavigateSession={(sessionId) => {
                      const sess = analysis.sessions.find(s => s.session_id === sessionId);
                      if (sess) handleSelectSession(sess);
                    }}
                  />
                )}
                {currentTab === 'findings' && (
                  <CryptographicFindings
                    analysis={analysis}
                    onSelectSessionId={(sessionId) => {
                      const sess = analysis.sessions.find(s => s.session_id === sessionId);
                      if (sess) handleSelectSession(sess);
                    }}
                  />
                )}
                {currentTab === 'ai_risk' && (
                  <AIRiskAnalysis
                    analysis={analysis}
                    onNavigateTab={handleNavigateTab}
                  />
                )}
                {currentTab === 'anomalies' && (
                  <TLSAnomalyDetection
                    analysis={analysis}
                    onNavigateSession={(sessionId) => {
                      const sess = analysis.sessions.find(s => s.session_id === sessionId);
                      if (sess) handleSelectSession(sess);
                    }}
                  />
                )}
                {currentTab === 'threat_matrix' && (
                  <ThreatPrioritization
                    analysis={analysis}
                    onNavigateTab={handleNavigateTab}
                  />
                )}
                {currentTab === 'security_posture' && (
                  <SecurityPosture
                    analysis={analysis}
                    onNavigateTab={handleNavigateTab}
                  />
                )}
                {currentTab === 'reports' && (
                  <Reports analysis={analysis} />
                )}
                {currentTab === 'settings' && (
                  <Settings analysis={analysis} />
                )}
              </>
            )
          ) : (
            <div className="flex items-center justify-center h-64 text-slate-400 text-xs font-mono">
              Loading forensic datasets...
            </div>
          )}
        </main>
      </div>
    </div>
  );
}

export default App;
