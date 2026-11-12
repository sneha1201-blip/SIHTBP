'use client';

import React, { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import { ShieldAlert, Lock, User, Eye, EyeOff, Loader2, AlertCircle, CheckCircle2 } from 'lucide-react';
import { loginUser, getAuthToken } from '../../lib/api';

export default function LoginPage() {
  const router = useRouter();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  // If already authenticated with valid token, redirect to dashboard
  useEffect(() => {
    const token = getAuthToken();
    if (token) {
      router.push('/');
    }
  }, [router]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setErrorMessage('Please enter both username and password.');
      return;
    }

    setIsLoading(true);
    setErrorMessage(null);
    setSuccessMessage(null);

    try {
      const res = await loginUser({
        username: username.trim(),
        password: password,
      });

      setSuccessMessage(`Authenticated as ${res.user.username} (${res.user.role}). Accessing secure console...`);
      setTimeout(() => {
        router.push('/');
      }, 700);
    } catch (err: any) {
      console.error('Authentication failure:', err);
      if (err.response?.status === 401) {
        setErrorMessage('Invalid credentials. Check your username and password.');
      } else if (err.response?.status === 429) {
        setErrorMessage('Authentication rate limit reached. Please wait before retrying.');
      } else if (!err.response) {
        setErrorMessage('Forensic API service unreachable. Verify the backend is running at http://localhost:8000.');
      } else {
        setErrorMessage(err.response?.data?.detail || 'Authentication failed. Please verify access authorization.');
      }
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col items-center justify-center p-4 selection:bg-cyan-500 selection:text-white relative overflow-hidden">
      {/* Ambient Cyber Grid Background Glow */}
      <div className="absolute inset-0 bg-[radial-gradient(ellipse_80%_80%_at_50%_-20%,rgba(14,165,233,0.15),rgba(255,255,255,0))] pointer-events-none" />

      <div className="relative w-full max-w-md bg-slate-900/90 border border-slate-800 rounded-2xl shadow-2xl backdrop-blur-xl p-8 flex flex-col gap-6 animate-fade-in">
        {/* Institutional Header */}
        <div className="flex flex-col items-center text-center gap-3">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-tr from-cyan-600 to-blue-500 p-0.5 shadow-xl shadow-cyan-500/20 flex items-center justify-center">
            <div className="w-full h-full bg-slate-950 rounded-[14px] flex items-center justify-center">
              <ShieldAlert className="w-7 h-7 text-cyan-400" />
            </div>
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white flex items-center justify-center gap-2">
              AICTE Cyber Security Cell
            </h1>
            <p className="text-xs text-cyan-400 font-mono mt-0.5">
              Email Threat Intelligence Platform | PS 26106
            </p>
          </div>
          <p className="text-xs text-slate-400 mt-1 max-w-xs">
            Enter authorized security credentials to access Section 63 BSA 2023 evidence dossiers and live graph telemetry.
          </p>
        </div>

        {/* Error Alert Banner */}
        {errorMessage && (
          <div className="bg-red-950/80 border border-red-800/80 rounded-xl px-4 py-3 flex items-start gap-3 text-red-200 text-xs shadow-lg animate-shake">
            <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold">Access Denied</p>
              <p className="text-red-300/90 mt-0.5">{errorMessage}</p>
            </div>
          </div>
        )}

        {/* Success Alert Banner */}
        {successMessage && (
          <div className="bg-emerald-950/80 border border-emerald-800/80 rounded-xl px-4 py-3 flex items-start gap-3 text-emerald-200 text-xs shadow-lg">
            <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-semibold">Security Clearance Verified</p>
              <p className="text-emerald-300/90 mt-0.5">{successMessage}</p>
            </div>
          </div>
        )}

        {/* Authentication Form */}
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
              <User className="w-3.5 h-3.5 text-cyan-400" />
              <span>Analyst Identity / Username</span>
            </label>
            <div className="relative">
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="e.g. analyst or secops_lead"
                autoComplete="username"
                required
                className="w-full bg-slate-950/80 border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 rounded-xl px-3.5 py-2.5 text-sm text-white placeholder-slate-500 transition outline-none font-mono"
              />
            </div>
          </div>

          <div className="flex flex-col gap-1.5">
            <label className="text-xs font-semibold text-slate-300 flex items-center gap-1.5">
              <Lock className="w-3.5 h-3.5 text-cyan-400" />
              <span>Password</span>
            </label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                autoComplete="current-password"
                required
                className="w-full bg-slate-950/80 border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 rounded-xl px-3.5 py-2.5 text-sm text-white placeholder-slate-500 transition outline-none pr-10"
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 transition"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className={`w-full mt-2 py-2.5 px-4 rounded-xl text-sm font-bold flex items-center justify-center gap-2 transition shadow-lg ${
              isLoading
                ? 'bg-slate-800 text-slate-400 cursor-not-allowed'
                : 'bg-cyan-500 hover:bg-cyan-400 text-slate-950 shadow-cyan-500/20 active:scale-[0.98]'
            }`}
          >
            {isLoading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                <span>Verifying Cryptographic Credentials...</span>
              </>
            ) : (
              <span>Sign In to Forensic Console</span>
            )}
          </button>
        </form>

        {/* Security Footnote */}
        <div className="pt-2 border-t border-slate-800/80 text-center">
          <p className="text-[11px] text-slate-400">
            Protected under Government of India Digital Evidence Admissibility Guidelines.
          </p>
          <p className="text-[10px] text-slate-400 font-mono mt-0.5">
            All authentication attempts are hashed and written to the immutable audit chain.
          </p>
        </div>
      </div>
    </div>
  );
}

