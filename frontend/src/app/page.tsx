'use client';

import React, { useState, useEffect } from 'react';
import dynamic from 'next/dynamic';
import { TopBar } from '../components/TopBar';
import { ThreatScoreGauge } from '../components/ThreatScoreGauge';
import { AuthBadges } from '../components/AuthBadges';
import { HeaderMismatchTable } from '../components/HeaderMismatchTable';
import { NlpIntentViewer } from '../components/NlpIntentViewer';
import { IocDataTable } from '../components/IocDataTable';
import { CampaignGraph } from '../components/CampaignGraph';
import { AuditLedgerTable } from '../components/AuditLedgerTable';
import { IngestionModal } from '../components/IngestionModal';
import { MOCK_DOSSIERS, MOCK_GRAPH } from '../lib/mockData';
import { FullForensicDossier, CampaignGraphData } from '../lib/types';
import { fetchEvidenceDossier, fetchCampaignGraph } from '../lib/api';
import { Shield, Sparkles, AlertOctagon, Terminal } from 'lucide-react';

// SSR-Safe dynamic import for Leaflet Geotrace Map
const GeoTraceMap = dynamic(() => import('../components/GeoTraceMap'), {
  ssr: false,
  loading: () => (
    <div className="bg-cyber-card border border-cyber-border rounded-xl p-5 shadow-xl min-h-[420px] flex flex-col items-center justify-center gap-3">
      <div className="w-8 h-8 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
      <span className="text-xs font-mono text-cyan-400">Mounting GeoTrace Map Engine...</span>
    </div>
  ),
});

export default function SOCDashboardPage() {
  const [activeCaseKey, setActiveCaseKey] = useState<string>('bec-wire-fraud');
  const [dossier, setDossier] = useState<FullForensicDossier>(MOCK_DOSSIERS['bec-wire-fraud']);
  const [graphData, setGraphData] = useState<CampaignGraphData>(MOCK_GRAPH);
  const [isIngestionOpen, setIsIngestionOpen] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);

  // Switch scenario or update dossier
  const handleCaseChange = async (key: string) => {
    setActiveCaseKey(key);
    if (MOCK_DOSSIERS[key]) {
      setDossier(MOCK_DOSSIERS[key]);
    } else {
      setIsLoading(true);
      try {
        const live = await fetchEvidenceDossier(key);
        setDossier(live);
      } catch (e) {
        console.error('Failed to switch case:', e);
      } finally {
        setIsLoading(false);
      }
    }
  };

  // Initial backend sync if available
  useEffect(() => {
    async function loadInitialData() {
      try {
        const g = await fetchCampaignGraph();
        if (g && g.graph && g.graph.nodes.length > 0) {
          setGraphData(g);
        }
      } catch (err) {
        // Fallback already defaults to MOCK_GRAPH
      }
    }
    loadInitialData();
  }, []);

  const handleIngestionSuccess = (newDossier: FullForensicDossier) => {
    setDossier(newDossier);
    setActiveCaseKey('custom-ingested');
  };

  return (
    <div className="min-h-screen bg-cyber-dark text-slate-100 flex flex-col selection:bg-cyan-500 selection:text-white">
      {/* Global Top Bar */}
      <TopBar
        caseId={dossier.email.id}
        sha256={dossier.email.sha256_hash}
        subject={dossier.email.subject}
        activeCaseKey={activeCaseKey}
        onCaseChange={handleCaseChange}
        onOpenIngest={() => setIsIngestionOpen(true)}
      />

      {/* Main Dashboard Container */}
      <main className="flex-1 max-w-[1600px] w-full mx-auto p-4 md:p-6 space-y-6">
        {/* Banner Alert for Active Investigation */}
        <div className="bg-slate-900/80 border border-cyber-border rounded-xl px-5 py-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3 shadow-lg">
          <div className="flex items-center gap-3">
            <div className={`w-3 h-3 rounded-full animate-pulse ${
              dossier.forensic_analysis.verdict === 'MALICIOUS' || dossier.forensic_analysis.verdict === 'BEC'
                ? 'bg-rose-500 ring-4 ring-rose-500/20'
                : dossier.forensic_analysis.verdict === 'PHISHING' || dossier.forensic_analysis.verdict === 'SUSPICIOUS'
                ? 'bg-amber-500 ring-4 ring-amber-500/20'
                : 'bg-emerald-500 ring-4 ring-emerald-500/20'
            }`} />
            <div>
              <div className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                <span>Active Target Subject:</span>
                <span className="font-mono text-cyan-300 font-bold">{dossier.email.subject}</span>
              </div>
              <div className="text-[11px] text-slate-400 mt-0.5">
                Ingested: <span className="font-mono text-slate-300">{dossier.email.ingested_at || 'Just Now'}</span> &bull; Sender: <span className="font-mono text-slate-300">{dossier.email.sender_email}</span> &bull; Primary Recipient: <span className="font-mono text-slate-300">{dossier.email.recipient_list[0] || 'Unknown'}</span>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 text-xs">
            <span className="text-slate-400">Section 63 BSA Status:</span>
            <span className="bg-emerald-950 text-emerald-300 border border-emerald-800 px-2.5 py-1 rounded font-mono font-bold text-[11px]">
              ADMISSIBLE EVIDENCE
            </span>
          </div>
        </div>

        {/* SECTION 1: Forensic Assessment Matrix (3 Columns) */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Threat Score Gauge */}
          <div className="h-full">
            <ThreatScoreGauge analysis={dossier.forensic_analysis} />
          </div>

          {/* RFC Authentication Protocol Verification */}
          <div className="h-full">
            <AuthBadges analysis={dossier.forensic_analysis} />
          </div>

          {/* RFC 5322 Identity & Spoofing Mismatch Matrix */}
          <div className="h-full">
            <HeaderMismatchTable
              email={dossier.email}
              analysis={dossier.forensic_analysis}
            />
          </div>
        </div>

        {/* SECTION 2: Protocol Geolocation & AI NLP Analysis (2 Columns) */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Hop-by-Hop Visual Geotrace Leaflet Map */}
          <div>
            <GeoTraceMap hops={dossier.header_hops} />
          </div>

          {/* AI NLP Intent & Urgency Content Viewer */}
          <div>
            <NlpIntentViewer
              bodyText={dossier.email.body_plain}
              subject={dossier.email.subject}
              analysis={dossier.forensic_analysis}
            />
          </div>
        </div>

        {/* SECTION 3: Threat Indicators & Intelligence Graph (2 Columns) */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Extracted Indicators of Compromise (IoCs) */}
          <div>
            <IocDataTable indicators={dossier.threat_indicators} />
          </div>

          {/* Campaign & Cross-Incident Correlation Graph */}
          <div>
            <CampaignGraph
              graphData={graphData}
              activeEmailId={dossier.email.id}
            />
          </div>
        </div>

        {/* SECTION 4: Cryptographic Tamper-Evident Audit Ledger */}
        <div>
          <AuditLedgerTable
            logs={dossier.audit_logs}
            masterSha256={dossier.email.sha256_hash}
          />
        </div>
      </main>

      {/* Global Ingestion Modal */}
      <IngestionModal
        isOpen={isIngestionOpen}
        onClose={() => setIsIngestionOpen(false)}
        onAnalysisSuccess={handleIngestionSuccess}
      />

      {/* Footer Legal & Compliance Disclaimer */}
      <footer className="border-t border-cyber-border py-4 px-6 text-center text-xs text-slate-500 bg-slate-950/80">
        <p>
          AICTE Cyber Security Cell &bull; Smart India Hackathon (SIH ID: 26106) Platform &bull; Forensic Evidence Compliance under Section 63 of Bharatiya Sakshya Adhiniyam, 2023 (BSA) & Section 65B of Indian Evidence Act, 1872.
        </p>
      </footer>
    </div>
  );
}

