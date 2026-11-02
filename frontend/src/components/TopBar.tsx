'use client';

import React, { useState } from 'react';
import {
  ShieldAlert,
  Copy,
  Check,
  FileDown,
  UploadCloud,
  Layers,
  ExternalLink,
} from 'lucide-react';
import { copyToClipboard } from '../lib/utils';
import { downloadForensicReportPdf } from '../lib/api';

interface TopBarProps {
  caseId: string;
  sha256: string;
  subject: string;
  activeCaseKey: string;
  onCaseChange: (caseKey: string) => void;
  onOpenIngest: () => void;
}

export function TopBar({
  caseId,
  sha256,
  subject,
  activeCaseKey,
  onCaseChange,
  onOpenIngest,
}: TopBarProps) {
  const [copiedSha, setCopiedSha] = useState(false);
  const [downloadingPdf, setDownloadingPdf] = useState(false);

  const handleCopySha = async () => {
    const ok = await copyToClipboard(sha256);
    if (ok) {
      setCopiedSha(true);
      setTimeout(() => setCopiedSha(false), 2000);
    }
  };

  const handleDownloadPdf = async () => {
    setDownloadingPdf(true);
    try {
      await downloadForensicReportPdf(caseId, sha256);
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

        {/* Center: Demo Case Switcher for Presentations */}
        <div className="flex items-center gap-2 bg-slate-900/80 px-3 py-1.5 rounded-lg border border-slate-800">
          <Layers className="w-4 h-4 text-slate-400" />
          <span className="text-xs font-semibold text-slate-400">Scenario:</span>
          <select
            value={activeCaseKey}
            onChange={(e) => onCaseChange(e.target.value)}
            className="bg-transparent text-xs font-medium text-cyan-300 focus:outline-none cursor-pointer"
          >
            <option value="bec-wire-fraud" className="bg-slate-900 text-white">
              Case 2: Executive BEC Wire Fraud (94/100)
            </option>
            <option value="tor-phishing" className="bg-slate-900 text-white">
              Case 3: Tor Exit Node Harvester (98/100)
            </option>
            <option value="homograph-attack" className="bg-slate-900 text-white">
              Case 4: Cyrillic Homograph 'а' (88/100)
            </option>
            <option value="falconshield-cluster" className="bg-slate-900 text-white">
              Case 5: Operation FalconShield Cluster (92/100)
            </option>
            <option value="legitimate-circular" className="bg-slate-900 text-white">
              Case 1: Legitimate AICTE Circular (12/100)
            </option>
          </select>
        </div>

        {/* Right: Master Hash & Action Buttons */}
        <div className="flex flex-wrap items-center gap-3">
          {/* Master SHA-256 Chip */}
          <div className="hidden xl:flex items-center gap-2 bg-slate-950/90 px-3 py-1.5 rounded-lg border border-slate-800 text-xs">
            <span className="text-slate-400 font-semibold">SHA-256:</span>
            <code className="text-cyan-400 font-mono text-[11px]">
              {sha256 ? `${sha256.slice(0, 10)}...${sha256.slice(-6)}` : 'Generating...'}
            </code>
            <button
              onClick={handleCopySha}
              title="Copy Evidence SHA-256 Digest"
              className="p-1 hover:text-cyan-300 text-slate-400 transition"
            >
              {copiedSha ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>

          {/* Section 65B PDF Dossier Button */}
          <button
            onClick={handleDownloadPdf}
            disabled={downloadingPdf}
            className="flex items-center gap-1.5 bg-slate-900 hover:bg-slate-800 text-slate-200 border border-slate-700/80 px-3.5 py-1.5 rounded-lg text-xs font-semibold shadow-sm transition active:scale-95 disabled:opacity-50"
          >
            <FileDown className={`w-3.5 h-3.5 text-emerald-400 ${downloadingPdf ? 'animate-bounce' : ''}`} />
            <span>{downloadingPdf ? 'Generating...' : 'Section 65B PDF'}</span>
          </button>

          {/* New Investigation Ingestion Button */}
          <button
            onClick={onOpenIngest}
            className="flex items-center gap-1.5 bg-cyan-600 hover:bg-cyan-500 text-white font-semibold px-4 py-1.5 rounded-lg text-xs shadow-md shadow-cyan-600/30 transition active:scale-95"
          >
            <UploadCloud className="w-3.5 h-3.5" />
            <span>New Investigation</span>
          </button>
        </div>
      </div>
    </header>
  );
}

