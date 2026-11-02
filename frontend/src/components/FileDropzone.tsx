'use client';

import React, { useState, useRef, DragEvent, ChangeEvent } from 'react';
import { UploadCloud, FileText, CheckCircle2, AlertCircle, Loader2, Hash, Shield } from 'lucide-react';
import { computeClientSha256 } from '../lib/utils';
import { analyzeEmailFile } from '../lib/api';
import { FullForensicDossier } from '../lib/types';

interface FileDropzoneProps {
  onSuccess: (dossier: FullForensicDossier) => void;
  onCancel?: () => void;
}

export function FileDropzone({ onSuccess, onCancel }: FileDropzoneProps) {
  const [dragActive, setDragActive] = useState<boolean>(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [computedSha256, setComputedSha256] = useState<string | null>(null);
  const [isHashing, setIsHashing] = useState<boolean>(false);
  const [isAnalyzing, setIsAnalyzing] = useState<boolean>(false);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const processFile = async (file: File) => {
    setErrorMsg(null);
    const ext = file.name.split('.').pop()?.toLowerCase();
    if (ext !== 'eml' && ext !== 'msg') {
      setErrorMsg('Unsupported file format. Please upload an RFC 822 (.eml) or Outlook (.msg) evidence file.');
      return;
    }

    setSelectedFile(file);
    setIsHashing(true);
    try {
      const sha256 = await computeClientSha256(file);
      setComputedSha256(sha256);
    } catch (err) {
      console.error('Error calculating client SHA-256:', err);
      setErrorMsg('Failed to compute client-side SHA-256 hash.');
    } finally {
      setIsHashing(false);
    }
  };

  const handleDrag = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === 'dragenter' || e.type === 'dragover') {
      setDragActive(true);
    } else if (e.type === 'dragleave') {
      setDragActive(false);
    }
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      processFile(e.target.files[0]);
    }
  };

  const handleIngest = async () => {
    if (!selectedFile) return;
    setIsAnalyzing(true);
    setErrorMsg(null);
    try {
      const dossier = await analyzeEmailFile(selectedFile);
      onSuccess(dossier);
    } catch (err: any) {
      console.error('Analysis failed:', err);
      setErrorMsg(err?.message || 'Forensic analysis failed. Please verify server connection.');
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Drag & Drop Area */}
      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition flex flex-col items-center justify-center min-h-[220px] ${
          dragActive
            ? 'border-cyan-400 bg-cyan-950/20 shadow-lg shadow-cyan-500/10'
            : selectedFile
            ? 'border-emerald-500/50 bg-emerald-950/10'
            : 'border-slate-800 bg-slate-950/60 hover:border-slate-700 hover:bg-slate-950/80'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          accept=".eml,.msg,message/rfc822"
          className="hidden"
          onChange={handleFileChange}
        />

        <div className="w-14 h-14 rounded-full bg-slate-900 border border-slate-800 flex items-center justify-center mb-3">
          {isHashing ? (
            <Loader2 className="w-6 h-6 text-cyan-400 animate-spin" />
          ) : selectedFile ? (
            <FileText className="w-6 h-6 text-emerald-400" />
          ) : (
            <UploadCloud className="w-6 h-6 text-slate-400" />
          )}
        </div>

        {selectedFile ? (
          <div>
            <div className="font-semibold text-slate-200 text-sm mb-1">{selectedFile.name}</div>
            <div className="text-xs text-slate-400 font-mono">
              {(selectedFile.size / 1024).toFixed(2)} KB &bull; Type: {selectedFile.name.split('.').pop()?.toUpperCase()}
            </div>
          </div>
        ) : (
          <div>
            <div className="text-sm font-semibold text-slate-200 mb-1">
              Drag and drop email evidence file here
            </div>
            <div className="text-xs text-slate-400">
              Supports raw RFC 822 <span className="font-mono text-cyan-400">.eml</span> and Outlook <span className="font-mono text-cyan-400">.msg</span> files
            </div>
          </div>
        )}
      </div>

      {/* Error Message */}
      {errorMsg && (
        <div className="flex items-center gap-2 text-xs text-rose-400 bg-rose-950/40 border border-rose-800 px-3 py-2 rounded-lg">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Client-side SHA-256 Hashing Status */}
      {computedSha256 && (
        <div className="bg-slate-950/80 border border-cyber-border rounded-lg p-3 text-xs flex flex-col gap-1.5">
          <div className="flex items-center justify-between text-slate-400 text-[11px]">
            <span className="flex items-center gap-1 font-semibold text-slate-300">
              <Hash className="w-3.5 h-3.5 text-cyan-400" /> Client-Side WebCrypto SHA-256 Checksum:
            </span>
            <span className="text-emerald-400 flex items-center gap-1 font-mono">
              <CheckCircle2 className="w-3.5 h-3.5" /> Calculated
            </span>
          </div>
          <div className="font-mono text-[11px] text-cyan-300 bg-slate-900 px-2 py-1 rounded border border-slate-800 break-all select-all">
            {computedSha256}
          </div>
          <div className="text-[10px] text-slate-500">
            Hash computed in browser memory prior to ingestion — guarantees Section 63 BSA 2023 chain of custody.
          </div>
        </div>
      )}

      {/* Ingestion Action Buttons */}
      <div className="flex items-center justify-end gap-3 pt-2">
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
          disabled={!selectedFile || isHashing || isAnalyzing}
          onClick={handleIngest}
          className={`px-5 py-2 rounded-lg text-xs font-semibold flex items-center gap-2 transition shadow-lg ${
            !selectedFile || isHashing || isAnalyzing
              ? 'bg-slate-800 text-slate-500 cursor-not-allowed'
              : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-cyan-500/20 font-bold'
          }`}
        >
          {isAnalyzing ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              <span>Running Deep Forensic Engine...</span>
            </>
          ) : (
            <>
              <Shield className="w-4 h-4" />
              <span>Ingest & Run Forensic Pipeline</span>
            </>
          )}
        </button>
      </div>
    </div>
  );
}

export default FileDropzone;

