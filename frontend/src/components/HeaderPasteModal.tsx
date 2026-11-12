'use client';

import React, { useState } from 'react';
import { Terminal, Shield, AlertCircle, Loader2 } from 'lucide-react';
import { analyzeEmailHeaders } from '../lib/api';
import { FullForensicDossier } from '../lib/types';

interface HeaderPasteModalProps {
  onSuccess: (dossier: FullForensicDossier) => void;
  onCancel?: () => void;
}

export function HeaderPasteModal({ onSuccess, onCancel }: HeaderPasteModalProps) {
  const [rawHeaders, setRawHeaders] = useState<string>('');
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [progressPercent, setProgressPercent] = useState<number>(0);
  const [jobStage, setJobStage] = useState<string>('');
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleAnalyze = async () => {
    if (!rawHeaders.trim()) {
      setErrorMsg('Please paste RFC 822 MIME headers before analyzing.');
      return;
    }

    setIsAnalyzing(true);
    setErrorMsg(null);
    setProgressPercent(10);
    setJobStage('QUEUED');
    try {
      const dossier = await analyzeEmailHeaders(rawHeaders, (job) => {
        setProgressPercent(job.progress_percent);
        setJobStage(job.stage.replace(/_/g, ' '));
      });
      onSuccess(dossier);
    } catch (err: any) {
      console.error('Header analysis failed:', err);
      setErrorMsg(err?.message || 'Header analysis failed. Please verify headers syntax.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Forensic Header Guidance Banner */}
      <div className="flex items-center justify-between gap-2 pb-2 border-b border-slate-800">
        <span className="text-xs text-slate-300 font-medium flex items-center gap-1.5">
          <Terminal className="w-3.5 h-3.5 text-cyan-400" /> RFC 822 / MIME Header Triage
        </span>
        <span className="text-[11px] text-slate-500 font-mono">
          Paste unedited headers directly from your email client
        </span>
      </div>

      {/* Textarea */}
      <div className="relative">
        <textarea
          rows={12}
          value={rawHeaders}
          onChange={(e) => setRawHeaders(e.target.value)}
          aria-label="Raw RFC 822 / MIME email headers input"
          className="w-full bg-slate-950 font-mono text-xs text-slate-200 border border-cyber-border rounded-xl p-4 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 selection:bg-cyan-500/30"
          spellCheck={false}
        />
        <div className="text-[10px] text-slate-500 mt-1 flex justify-between">
          <span>Accepts raw `Received:`, `Authentication-Results:`, `From:`, and `Return-Path:` lines</span>
          <span>{rawHeaders.length} characters</span>
        </div>
      </div>

      {/* Error Message */}
      {errorMsg && (
        <div className="flex items-center gap-2 text-xs text-rose-400 bg-rose-950/40 border border-rose-800 px-3 py-2 rounded-lg">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Real-Time SSE Pipeline Progress Streaming */}
      {isAnalyzing && (
        <div className="bg-slate-950/90 border border-cyan-500/30 rounded-xl p-4 flex flex-col gap-2 animate-fade-in shadow-lg shadow-cyan-950/30">
          <div className="flex items-center justify-between text-xs">
            <span className="flex items-center gap-2 font-mono text-cyan-400 font-semibold">
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              <span>STAGE: {jobStage || 'PIPELINE_ACTIVE'}</span>
            </span>
            <span className="font-mono text-white font-bold">{progressPercent}%</span>
          </div>
          <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden border border-slate-800">
            <div
              className="bg-gradient-to-r from-cyan-500 to-blue-500 h-2 rounded-full transition-all duration-300"
              style={{ width: `${Math.max(5, progressPercent)}%` }}
            />
          </div>
          <p className="text-[10px] text-slate-400 font-mono">
            Streaming live telemetry from backend via Server-Sent Events (SSE).
          </p>
        </div>
      )}

      {/* Action Buttons */}
      <div className="flex items-center justify-end gap-3 pt-1">
        {onCancel && (
          <button
            type="button"
            onClick={onCancel}
            className="px-4 py-2 rounded-lg text-xs font-semibold text-slate-400 hover:text-white transition"
          >
            Cancel
          </button>
        )}
        <button
          type="button"
          disabled={!rawHeaders.trim() || isAnalyzing}
          onClick={handleAnalyze}
          className={`px-5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition shadow-lg ${
            !rawHeaders.trim() || isAnalyzing
              ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
              : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-cyan-500/20 font-bold'
          }`}
        >
          {isAnalyzing ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Analyzing Reverse MTA Hops...</span>
            </>
          ) : (
            <>
              <Shield className="w-4 h-4" />
              <span>Execute Header Forensics</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
}

export default HeaderPasteModal;

