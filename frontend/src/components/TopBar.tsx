'use client';

import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Copy,
  Check,
  FileDown,
  UploadCloud,
  Activity,
  LogOut,
  UserCheck,
} from 'lucide-react';
import { copyToClipboard } from '../lib/utils';
import { downloadForensicReportPdf, getStoredUser, logoutUser } from '../lib/api';

interface TopBarProps {
  caseId?: string;
  sha256?: string;
  subject?: string;
  backendOnline?: boolean;
  onOpenIngest: () => void;
}

export function TopBar({
  caseId,
  sha256,
  subject,
  backendOnline = true,
  onOpenIngest,
}: TopBarProps) {
  const [copiedSha, setCopiedSha] = useState(false);
  const [downloadingPdf, setDownloadingPdf] = useState(false);
  const [currentUser, setCurrentUser] = useState<{ username: string; role: string } | null>(null);

  useEffect(() => {
    setCurrentUser(getStoredUser());
  }, []);

  const handleCopySha = async () => {
    if (!sha256) return;
    const ok = await copyToClipboard(sha256);
    if (ok) {
      setCopiedSha(true);
      setTimeout(() => setCopiedSha(false), 2000);
    }
  };

  const handleDownloadPdf = async () => {
    if (!caseId || !sha256) return;
    setDownloadingPdf(true);
    try {
      await downloadForensicReportPdf(caseId, sha256);
    } catch (err) {
      console.error('PDF generation error:', err);
    } finally {
      setDownloadingPdf(false);
    }
  };

  return (
    <header className="bg-cyber-dark/95 backdrop-blur border-b border-cyber-border sticky top-0 z-50 px-6 py-3">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        {/* Left: AICTE Badge & Platform Identity */}
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-tr from-cyan-600 to-blue-500 p-0.5 shadow-lg shadow-cyan-500/20 flex items-center justify-center">
            <div className="w-full h-full bg-slate-950 rounded-[7px] flex items-center justify-center">
              <ShieldAlert className="w-5 h-5 text-cyan-400 animate-pulse" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-extrabold text-white tracking-wide uppercase">
                AICTE Cyber Defense Cell
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/60 font-bold">
                SIH ID: 26106
              </span>
            </div>
            <p className="text-xs text-slate-400">
              AI-Powered Email Threat Detection, GeoLocation & Forensic Intelligence Platform
            </p>
          </div>
        </div>

        {/* Center: Live Forensic Status & Backend Link */}
        <div className="flex items-center gap-2 bg-slate-900/80 px-3.5 py-1.5 rounded-lg border border-slate-800 text-xs">
          <div className={`w-2 h-2 rounded-full ${backendOnline ? 'bg-emerald-400 animate-pulse' : 'bg-red-400'}`} />
          <span className="text-slate-400 font-medium">Service:</span>
          <span className={backendOnline ? 'text-emerald-400 font-semibold' : 'text-red-400 font-semibold'}>
            {backendOnline ? 'ONLINE' : 'DISCONNECTED'}
          </span>
          <span className="text-slate-700">|</span>
          <Activity className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-slate-300 font-mono">
            {caseId ? `Case: ${caseId.slice(0, 8)}...` : 'No Active Case'}
          </span>
        </div>

        {/* Right: Master Hash & Action Buttons */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Master SHA-256 Chip */}
          {sha256 && (
            <div className="hidden xl:flex items-center gap-2 bg-slate-950/90 px-3 py-1.5 rounded-lg border border-slate-800 text-xs">
              <span className="text-slate-400 font-semibold">SHA-256:</span>
              <code className="text-cyan-400 font-mono text-[11px]">
                {`${sha256.slice(0, 10)}...${sha256.slice(-6)}`}
              </code>
              <button
                onClick={handleCopySha}
                title="Copy Evidence SHA-256 Digest"
                className="p-1 hover:text-cyan-300 text-slate-400 transition"
              >
                {copiedSha ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          )}

          {/* Section 63 BSA PDF Dossier Button */}
          {caseId && (
            <button
              onClick={handleDownloadPdf}
              disabled={downloadingPdf}
              className="flex items-center gap-1.5 bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700/80 px-3.5 py-1.5 rounded-lg text-xs font-semibold shadow-sm transition active:scale-95 disabled:opacity-50"
            >
              <FileDown className={`w-3.5 h-3.5 text-emerald-400 ${downloadingPdf ? 'animate-bounce' : ''}`} />
              <span>{downloadingPdf ? 'Generating...' : 'Section 63 BSA Certificate (PDF)'}</span>
            </button>
          )}

          {/* New Investigation Ingestion Button */}
          <button
            onClick={onOpenIngest}
            className="flex items-center gap-1.5 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold px-4 py-1.5 rounded-lg text-xs shadow-md shadow-cyan-500/20 transition active:scale-95"
          >
            <UploadCloud className="w-3.5 h-3.5" />
            <span>New Investigation</span>
          </button>

          {/* User Profile & Logout */}
          <div className="flex items-center gap-2 pl-2 border-l border-slate-800">
            <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-slate-900 border border-slate-800 text-xs">
              <UserCheck className="w-3.5 h-3.5 text-cyan-400" />
              <span className="font-mono text-slate-200">{currentUser?.username || 'analyst'}</span>
              <span className="text-[10px] text-cyan-400 bg-cyan-950 px-1 py-0.2 rounded font-bold">
                {currentUser?.role || 'ANALYST'}
              </span>
            </div>
            <button
              onClick={() => logoutUser()}
              title="Sign Out / Switch Analyst"
              className="p-1.5 rounded-lg bg-slate-900 hover:bg-red-950/60 border border-slate-800 hover:border-red-800 text-slate-400 hover:text-red-300 transition"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>
    </header>
  );
}
