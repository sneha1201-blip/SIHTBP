'use client';

import React, { useState } from 'react';
import { Terminal, Shield, AlertCircle, Loader2, Sparkles, FileText } from 'lucide-react';
import { analyzeEmailHeaders } from '../lib/api';
import { FullForensicDossier } from '../lib/types';

interface HeaderPasteModalProps {
  onSuccess: (dossier: FullForensicDossier) => void;
  onCancel?: () => void;
}

const SAMPLE_BEC_HEADERS = `Received: from mail-relay.aicte-india.org (14.139.245.10) by mx1.iitd.ac.in with ESMTP id m123456789;
    Thu, 29 Oct 2026 14:32:05 +0530
Received: from mail.chairman-aicte-desk.com (45.154.255.88) by mail-relay.aicte-india.org with ESMTP id h987654321;
    Thu, 29 Oct 2026 14:30:45 +0530
From: "Prof. T.G. Sitharam" <chairman@chairman-aicte-desk.com>
To: registrar@iitd.ac.in
Reply-To: executive-fund-desk@consultant.com
Subject: STRICTLY CONFIDENTIAL: Immediate Emergency Grant Allocation - NEQIP 2026
Date: Thu, 29 Oct 2026 14:30:12 +0530
Message-ID: <20261029143012.8841.aicte@chairman-aicte-desk.com>
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Authentication-Results: mx1.iitd.ac.in;
    spf=fail (sender IP 45.154.255.88 is not designated for aicte-india.org);
    dkim=none;
    dmarc=fail (p=reject) header.from=chairman-aicte-desk.com`;

const SAMPLE_HOMOGRAPH_HEADERS = `Received: from edge-mx.annauniv.edu (210.212.242.1) by mx1.annauniv.edu with ESMTPS id hop4;
    Fri, 30 Oct 2026 08:24:45 +0530
Received: from smtp-out.xn--icte-india-e1a.org (193.109.69.52) by edge-mx.annauniv.edu with ESMTPS id hop3;
    Fri, 30 Oct 2026 08:22:15 +0530
From: "AICTE Approval Bureau" <scrutiny@\u0430icte-india.org>
To: principal@annauniv.edu
Subject: URGENT DEFICIENCY NOTICE: Extension of Approval (EoA) 2026-27
Date: Fri, 30 Oct 2026 08:20:00 +0530
Message-ID: <aph2026-def-notice-098@xn--icte-india-e1a.org>
Authentication-Results: edge-mx.annauniv.edu;
    spf=pass smtp.mailfrom=xn--icte-india-e1a.org;
    dkim=pass header.d=xn--icte-india-e1a.org;
    dmarc=fail (p=reject) header.from=aicte-india.org`;

export function HeaderPasteModal({ onSuccess, onCancel }: HeaderPasteModalProps) {
  const [rawHeaders, setRawHeaders] = useState<string>('');
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const handleAnalyze = async () => {
    if (!rawHeaders.trim()) {
      setErrorMsg('Please paste RFC 822 MIME headers before analyzing.');
      return;
    }

    setIsAnalyzing(true);
    setErrorMsg(null);
    try {
      const dossier = await analyzeEmailHeaders(rawHeaders);
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
      {/* Sample presets bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-slate-800">
        <span className="text-xs text-slate-400 font-semibold flex items-center gap-1.5">
          <Terminal className="w-3.5 h-3.5 text-cyan-400" /> Quick Forensic Header Presets:
        </span>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setRawHeaders(SAMPLE_BEC_HEADERS)}
            className="text-[11px] px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-amber-300 border border-slate-800 transition flex items-center gap-1"
          >
            <Sparkles className="w-3 h-3 text-amber-400" /> Load BEC Wire Fraud
          </button>
          <button
            type="button"
            onClick={() => setRawHeaders(SAMPLE_HOMOGRAPH_HEADERS)}
            className="text-[11px] px-2.5 py-1 rounded bg-slate-900 hover:bg-slate-800 text-rose-300 border border-slate-800 transition flex items-center gap-1"
          >
            <Sparkles className="w-3 h-3 text-rose-400" /> Load Cyrillic Homograph
          </button>
        </div>
      </div>

      {/* Textarea */}
      <div className="relative">
        <textarea
          rows={12}
          value={rawHeaders}
          onChange={(e) => setRawHeaders(e.target.value)}
          placeholder={`Paste raw RFC 822 / MIME email headers here...
Example:
Received: from mail.attacker.com (185.220.101.5) by mx.victim.org...
From: "VIP Target" <vip@spoofed-domain.com>
Subject: Urgent Payment...`}
          className="w-full bg-slate-950 font-mono text-xs text-slate-200 border border-cyber-border rounded-xl p-4 placeholder-slate-600 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 selection:bg-cyan-500/30"
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

