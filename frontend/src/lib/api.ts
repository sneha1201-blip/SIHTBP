import axios from 'axios';
import { FullForensicDossier, CampaignGraphData } from './types';

export function getApiBase(): string {
  if (process.env.NEXT_PUBLIC_API_URL) {
    return process.env.NEXT_PUBLIC_API_URL;
  }
  if (typeof window !== 'undefined') {
    const protocol = window.location.protocol;
    const hostname = window.location.hostname || 'localhost';
    return `${protocol}//${hostname}:8000/api/v1`;
  }
  return 'http://localhost:8000/api/v1';
}

export const apiClient = axios.create({
  baseURL: getApiBase(),
  timeout: 60000,
});

// Manage authentication token in browser storage
export function getAuthToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('aicte_forensics_jwt');
}

export function setAuthToken(token: string): void {
  if (typeof window !== 'undefined') {
    localStorage.setItem('aicte_forensics_jwt', token);
  }
}

export function removeAuthToken(): void {
  if (typeof window !== 'undefined') {
    localStorage.removeItem('aicte_forensics_jwt');
    localStorage.removeItem('aicte_forensics_user');
  }
}

export function getStoredUser(): { username: string; role: string; email?: string } | null {
  if (typeof window === 'undefined') return null;
  const userJson = localStorage.getItem('aicte_forensics_user');
  if (!userJson) return null;
  try {
    return JSON.parse(userJson);
  } catch {
    return null;
  }
}

export function setStoredUser(user: { username: string; role: string; email?: string }): void {
  if (typeof window !== 'undefined') {
    localStorage.setItem('aicte_forensics_user', JSON.stringify(user));
  }
}

// Request interceptor ensuring Bearer token is attached and baseURL is dynamic
apiClient.interceptors.request.use((config) => {
  config.baseURL = getApiBase();
  const token = getAuthToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response interceptor redirecting 401 Unauthorized to /login
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401 && typeof window !== 'undefined') {
      const isLoginPath = window.location.pathname.startsWith('/login');
      if (!isLoginPath) {
        removeAuthToken();
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

// ---------------------------------------------------------------------------
// Authentication & RBAC APIs
// ---------------------------------------------------------------------------

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface AuthResponse {
  access_token: string;
  token_type: string;
  user: {
    id: string;
    username: string;
    email: string;
    role: string;
  };
}

export async function loginUser(credentials: LoginCredentials): Promise<AuthResponse> {
  const response = await axios.post<AuthResponse>(`${getApiBase()}/auth/login`, credentials);
  if (response.data && response.data.access_token) {
    setAuthToken(response.data.access_token);
    setStoredUser({
      username: response.data.user.username,
      role: response.data.user.role,
      email: response.data.user.email,
    });
  }
  return response.data;
}

export async function getCurrentUser(): Promise<any> {
  const response = await apiClient.get('/auth/me');
  return response.data;
}

export function logoutUser(): void {
  removeAuthToken();
  if (typeof window !== 'undefined') {
    window.location.href = '/login';
  }
}

// ---------------------------------------------------------------------------
// Asynchronous Ingestion & SSE Progress Streaming
// ---------------------------------------------------------------------------

export interface ForensicJobState {
  job_id: string;
  file_name: string;
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED';
  stage: string;
  progress_percent: number;
  evidence_id?: string;
  error_message?: string;
  result?: FullForensicDossier;
}

/**
 * Streams real-time Server-Sent Events (SSE) for an active forensic ingestion job.
 * Uses native fetch with ReadableStream to support Authorization Bearer headers.
 */
export async function streamJobProgress(
  jobId: string,
  onProgress?: (job: ForensicJobState) => void
): Promise<FullForensicDossier> {
  const token = getAuthToken();
  const streamUrl = `${getApiBase()}/forensics/jobs/${jobId}/stream`;

  const response = await fetch(streamUrl, {
    method: 'GET',
    headers: {
      Accept: 'text/event-stream',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
  });

  if (!response.ok) {
    throw new Error(`SSE stream connection failed with HTTP ${response.status}`);
  }

  if (!response.body) {
    throw new Error('ReadableStream not supported by browser environment.');
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8');
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const events = buffer.split('\n\n');
    buffer = events.pop() || '';

    for (const eventBlock of events) {
      const dataLine = eventBlock.split('\n').find((l) => l.startsWith('data:'));
      if (dataLine) {
        const jsonText = dataLine.replace(/^data:\s*/, '').trim();
        if (jsonText) {
          try {
            const jobData: ForensicJobState = JSON.parse(jsonText);
            if (onProgress) {
              onProgress(jobData);
            }
            if (jobData.status === 'COMPLETED') {
              if (jobData.result) {
                return jobData.result;
              }
              if (jobData.evidence_id) {
                return await fetchEvidenceDossier(jobData.evidence_id);
              }
            }
            if (jobData.status === 'FAILED') {
              throw new Error(jobData.error_message || 'Forensic analysis pipeline failed.');
            }
          } catch (err: unknown) {
            if (err instanceof Error && err.message.includes('Forensic analysis pipeline failed')) {
              throw err;
            }
          }
        }
      }
    }
  }

  // Fallback: poll job status endpoint if stream closed before completion event
  const pollRes = await apiClient.get<ForensicJobState>(`/forensics/jobs/${jobId}`);
  if (pollRes.data.status === 'COMPLETED') {
    if (pollRes.data.result) return pollRes.data.result;
    if (pollRes.data.evidence_id) return await fetchEvidenceDossier(pollRes.data.evidence_id);
  }
  throw new Error(pollRes.data.error_message || 'Forensic analysis terminated without result dossier.');
}

/**
 * Ingest an email file (.eml / .msg) for asynchronous forensic analysis with real-time SSE progress.
 */
export async function analyzeEmailFile(
  file: File,
  onProgress?: (job: ForensicJobState) => void
): Promise<FullForensicDossier> {
  const formData = new FormData();
  formData.append('file', file);

  const initResponse = await apiClient.post<ForensicJobState>('/forensics/analyze', formData);

  const job = initResponse.data;
  if (onProgress) {
    onProgress(job);
  }
  return await streamJobProgress(job.job_id, onProgress);
}

/**
 * Ingest raw RFC 822 email headers for asynchronous forensic analysis with real-time SSE progress.
 */
export async function analyzeEmailHeaders(
  rawHeaders: string,
  onProgress?: (job: ForensicJobState) => void
): Promise<FullForensicDossier> {
  const formData = new FormData();
  formData.append('raw_headers', rawHeaders);

  const initResponse = await apiClient.post<ForensicJobState>('/forensics/analyze', formData);

  const job = initResponse.data;
  if (onProgress) {
    onProgress(job);
  }
  return await streamJobProgress(job.job_id, onProgress);
}

// ---------------------------------------------------------------------------
// Intelligence, Graph & Dossier APIs
// ---------------------------------------------------------------------------

/**
 * Fetch a complete forensic dossier by evidence UUID.
 */
export async function fetchEvidenceDossier(id: string): Promise<FullForensicDossier> {
  const response = await apiClient.get<FullForensicDossier>(`/forensics/evidence/${id}`);
  return response.data;
}

/**
 * Fetch cross-incident campaign graph relationships with optional threat score and cluster type filters.
 */
export async function fetchCampaignGraph(minScore?: number, clusterType?: string): Promise<CampaignGraphData> {
  const params: Record<string, any> = {};
  if (minScore !== undefined) params.min_threat_score = minScore;
  if (clusterType && clusterType !== 'ALL') params.cluster_type = clusterType;
  const response = await apiClient.get<CampaignGraphData>('/campaigns/graph', { params });
  return response.data;
}

/**
 * Export all threat campaigns as an RFC-compliant STIX 2.1 JSON bundle.
 */
export async function downloadStixBundle(campaignId?: string): Promise<void> {
  const endpoint = campaignId ? `/campaigns/${campaignId}/stix` : '/campaigns/export/stix';
  const response = await apiClient.get(endpoint);
  const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(response.data, null, 2));
  const link = document.createElement('a');
  link.setAttribute('href', dataStr);
  link.setAttribute('download', `STIX_2.1_Threat_Bundle_${new Date().toISOString().slice(0, 10)}.json`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}

/**
 * Verify cryptographic hash-chain integrity of the evidence audit ledger.
 */
export async function verifyAuditChain(): Promise<{ valid: boolean; total_records: number; chain_head?: string; error?: string }> {
  const response = await apiClient.get('/forensics/audit/verify-chain');
  return response.data;
}

/**
 * Download a court-admissible Section 63 BSA 2023 forensic PDF dossier.
 */
export async function downloadForensicReportPdf(id: string, sha256: string): Promise<void> {
  const response = await apiClient.get(`/forensics/evidence/${id}/report`, {
    responseType: 'blob',
  });
  const blob = new Blob([response.data], { type: 'application/pdf' });
  const url = window.URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `Forensic_Dossier_BSA63_${sha256.slice(0, 12)}.pdf`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  window.URL.revokeObjectURL(url);
}
