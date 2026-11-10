'use client';

import React, { useState, useEffect, useCallback } from 'react';
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
import { FullForensicDossier, CampaignGraphData } from '../lib/types';
import { fetchCampaignGraph, fetchEvidenceDossier } from '../lib/api';
import { Shield, AlertTriangle, RefreshCw, UploadCloud, Search } from 'lucide-react';

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
  const [dossier, setDossier] = useState<FullForensicDossier | null>(null);
  const [graphData, setGraphData] = useState<CampaignGraphData>({
    graph: { total_nodes: 0, total_edges: 0, nodes: [], edges: [] },
  });
  const [isIngestionOpen, setIsIngestionOpen] = useState<boolean>(false);
  const [backendOnline, setBackendOnline] = useState<boolean>(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(false);

  // Sync live intelligence from backend
  const loadLiveIntelligence = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const g = await fetchCampaignGraph();
      if (g && g.graph) {
        setGraphData(g);
        setBackendOnline(true);
        // If graph has email nodes and no dossier is loaded, load the primary email node
        if (!dossier && g.graph.nodes && g.graph.nodes.length > 0) {
          const emailNode = g.graph.nodes.find((n: { type: string; id: string }) => n.type === 'email');
          if (emailNode) {
            try {
              const liveDossier = await fetchEvidenceDossier(emailNode.id);
              setDossier(liveDossier);
            } catch {
              // Non-fatal if specific dossier cannot load
            }
          }
        }
      }
    } catch (err: unknown) {
      console.error('Failed to connect to forensic backend:', err);
      setBackendOnline(false);
      setErrorMessage('Unable to communicate with the Forensic API at http://localhost:8000. Verify the backend service is running.');
    } finally {
      setIsLoading(false);
    }
  }, [dossier]);

  useEffect(() => {
    loadLiveIntelligence();
  }, [loadLiveIntelligence]);

  const handleIngestionSuccess = (newDossier: FullForensicDossier) => {
    setDossier(newDossier);
    setBackendOnline(true);
    setErrorMessage(null);
    loadLiveIntelligence();
  };

  return (
    <div className="min-h-screen bg-cyber-dark text-slate-100 flex flex-col selection:bg-cyan-500 selection:text-white">
      {/* Global Top Bar */}
      <TopBar
        caseId={dossier?.email.id}
        sha256={dossier?.email.sha256_hash}
        subject={dossier?.email.subject}
        backendOnline={backendOnline}
        onOpenIngest={() => setIsIngestionOpen(true)}
      />

      {/* Main Dashboard Container */}
      <main className="flex-1 max-w-[1600px] w-full mx-auto p-4 md:p-6 space-y-6">
        {/* Error Banner when Backend is Unreachable */}
        {errorMessage && (
          <div className="bg-red-950/80 border border-red-800 rounded-xl px-5 py-4 flex items-center justify-between text-red-200 shadow-xl">
            <div className="flex items-center gap-3">
              <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
              <div>
                <h4 className="text-sm font-bold">Forensic Service Connection Warning</h4>
                <p className="text-xs text-red-300/80">{errorMessage}</p>
              </div>
            </div>
            <button
              onClick={loadLiveIntelligence}
              disabled={isLoading}
              className="flex items-center gap-1.5 bg-red-900/60 hover:bg-red-800 border border-red-700 px-3 py-1.5 rounded-lg text-xs font-semibold transition active:scale-95 disabled:opacity-50"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
              <span>Retry</span>
            </button>
          </div>
        )}

        {/* Empty State: Awaiting Evidence Ingestion */}
        {!dossier && !isLoading && (
          <div className="bg-cyber-card border border-cyber-border rounded-2xl p-12 text-center max-w-2xl mx-auto my-12 shadow-2xl flex flex-col items-center gap-4">
            <div className="w-16 h-16 rounded-2xl bg-cyan-950/80 border border-cyan-800/80 flex items-center justify-center text-cyan-400 shadow-lg shadow-cyan-500/10">
              <Shield className="w-8 h-8" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white tracking-tight">AICTE Cyber Threat Intelligence Console</h2>
              <p className="text-xs text-slate-400 max-w-md mt-1">
                Authentic, evidence-backed forensic analysis compliant with Section 63 of the Bharatiya Sakshya Adhiniyam, 2023.
              </p>
            </div>
            <div className="flex items-center gap-3 mt-2">
              <button
                onClick={() => setIsIngestionOpen(true)}
                className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold px-5 py-2.5 rounded-xl text-xs shadow-lg shadow-cyan-600/30 transition active:scale-95"
              >
                <UploadCloud className="w-4 h-4" />
                <span>Ingest Evidence Artifact (.eml / .msg)</span>
              </button>
              <button
                onClick={loadLiveIntelligence}
                className="flex items-center gap-2 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-700 px-4 py-2.5 rounded-xl text-xs transition"
              >
                <Search className="w-4 h-4 text-slate-400" />
                <span>Query Active Case Database</span>
              </button>
            </div>
          </div>
        )}

        {/* Active Investigation Dossier */}
        {dossier && (
          <>
            {/* Banner Alert for Active Investigation */}
            <div className="bg-slate-900/80 border border-cyber-border rounded-xl px-5 py-3.5 flex flex-col md:flex-row md:items-center justify-between gap-3 shadow-lg">
              <div className="flex items-center gap-3">
                <div
                  className={`w-3 h-3 rounded-full animate-pulse ${
                    dossier.forensic_analysis.verdict === 'MALICIOUS' || dossier.forensic_analysis.verdict === 'BEC'
                      ? 'bg-rose-500 ring-4 ring-rose-500/20'
                      : dossier.forensic_analysis.verdict === 'PHISHING' || dossier.forensic_analysis.verdict === 'SUSPICIOUS'
                      ? 'bg-amber-500 ring-4 ring-amber-500/20'
                      : 'bg-emerald-500 ring-4 ring-emerald-500/20'
                  }`}
                />
                <div>
                  <div className="text-xs font-semibold text-slate-200 flex items-center gap-2">
                    <span>Active Target Subject:</span>
                    <span className="font-mono text-cyan-300 font-bold">{dossier.email.subject || '(No Subject)'}</span>
                  </div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    Ingested:{' '}
                    <span className="font-mono text-slate-300">
                      {dossier.email.ingested_at ? new Date(dossier.email.ingested_at).toUTCString() : 'Just Now'}
                    </span>{' '}
                    &bull; Sender: <span className="font-mono text-slate-300">{dossier.email.sender_email || 'Unknown'}</span>{' '}
                    &bull; Primary Recipient:{' '}
                    <span className="font-mono text-slate-300">{dossier.email.recipient_list[0] || 'Unknown'}</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2 text-xs">
                <span className="text-slate-400">Statutory Compliance:</span>
                <span className="bg-emerald-950 text-emerald-300 border border-emerald-800 px-2.5 py-1 rounded font-mono font-bold text-[11px]">
                  SECTION 63 BSA 2023 CERTIFIED
                </span>
              </div>
            </div>

            {/* SECTION 1: Forensic Assessment Matrix (3 Columns) */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="h-full">
                <ThreatScoreGauge analysis={dossier.forensic_analysis} />
              </div>
              <div className="h-full">
                <AuthBadges analysis={dossier.forensic_analysis} />
              </div>
              <div className="h-full">
                <HeaderMismatchTable email={dossier.email} analysis={dossier.forensic_analysis} />
              </div>
            </div>

            {/* SECTION 2: Protocol Geolocation & AI NLP Analysis (2 Columns) */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div>
                <GeoTraceMap hops={dossier.header_hops} />
              </div>
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
              <div>
                <IocDataTable indicators={dossier.threat_indicators} />
              </div>
              <div>
                <CampaignGraph graphData={graphData} activeEmailId={dossier.email.id} />
              </div>
            </div>

            {/* SECTION 4: Cryptographic Tamper-Evident Audit Ledger */}
            <div>
              <AuditLedgerTable logs={dossier.audit_logs} masterSha256={dossier.email.sha256_hash} />
            </div>
          </>
        )}
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
          AICTE Cyber Security Cell &bull; Smart India Hackathon (SIH ID: 26106) Platform &bull; Forensic Evidence Admissibility under Section 63 of the Bharatiya Sakshya Adhiniyam (BSA), 2023.
        </p>
      </footer>
    </div>
  );
}
