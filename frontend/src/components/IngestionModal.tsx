'use client';

import React, { useState } from 'react';
import { X, UploadCloud, Terminal, ShieldAlert, Cpu } from 'lucide-react';
import { FileDropzone } from './FileDropzone';
import { HeaderPasteModal } from './HeaderPasteModal';
import { FullForensicDossier } from '../lib/types';

interface IngestionModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAnalysisSuccess: (dossier: FullForensicDossier) => void;
}

export function IngestionModal({ isOpen, onClose, onAnalysisSuccess }: IngestionModalProps) {
  const [activeTab, setActiveTab] = useState<'FILE' | 'HEADERS'>('FILE');

  if (!isOpen) return null;

  const handleSuccess = (dossier: FullForensicDossier) => {
    onAnalysisSuccess(dossier);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-fade-in">
      <div className="relative w-full max-w-2xl bg-cyber-card border border-cyber-border rounded-2xl shadow-2xl overflow-hidden flex flex-col">
        {/* Modal Top Header */}
        <div className="flex items-center justify-between p-5 border-b border-cyber-border bg-slate-950/60">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Cpu className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white tracking-wide flex items-center gap-2">
                Ingest Email Evidence & Run Forensic Triage
              </h2>
              <p className="text-[11px] text-slate-400">
                Supports Section 63 BSA 2023 tamper-evident intake verification
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="w-8 h-8 rounded-lg bg-slate-900 border border-slate-800 flex items-center justify-center text-slate-400 hover:text-white hover:bg-slate-800 transition"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Tab Toggle Bar */}
        <div className="flex border-b border-cyber-border bg-slate-950/40 px-5 pt-3 gap-2">
          <button
            onClick={() => setActiveTab('FILE')}
            className={`flex items-center gap-2 pb-3 px-3 text-xs font-semibold border-b-2 transition ${
              activeTab === 'FILE'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <UploadCloud className="w-4 h-4" />
            <span>Upload Raw Evidence (.eml / .msg)</span>
          </button>

          <button
            onClick={() => setActiveTab('HEADERS')}
            className={`flex items-center gap-2 pb-3 px-3 text-xs font-semibold border-b-2 transition ${
              activeTab === 'HEADERS'
                ? 'border-cyan-400 text-cyan-400'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-4 h-4" />
            <span>Paste RFC 822 MIME Headers</span>
          </button>
        </div>

        {/* Modal Content Body */}
        <div className="p-6">
          {activeTab === 'FILE' ? (
            <FileDropzone onSuccess={handleSuccess} onCancel={onClose} />
          ) : (
            <HeaderPasteModal onSuccess={handleSuccess} onCancel={onClose} />
          )}
        </div>
      </div>
    </div>
  );
}

export default IngestionModal;

