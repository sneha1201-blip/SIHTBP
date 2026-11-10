import axios from 'axios';
import { FullForensicDossier, CampaignGraphData } from './types';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
});

// Manage authentication token
export function getAuthToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('aicte_forensics_jwt');
}

export function setAuthToken(token: string): void {
  if (typeof window !== 'undefined') {
    localStorage.setItem('aicte_forensics_jwt', token);
  }
}

// Request interceptor ensuring Bearer token is attached
apiClient.interceptors.request.use(async (config) => {
  let token = getAuthToken();

  // If no token exists in browser session, auto-authenticate as analyst
  if (!token && typeof window !== 'undefined') {
    try {
      const authRes = await axios.post(`${API_BASE}/auth/login`, {
        username: 'analyst',
        password: 'AnalystPassword@2026',
      });
      if (authRes.data && authRes.data.access_token) {
        token = authRes.data.access_token;
        setAuthToken(token!);
      }
    } catch {
      // Allow request to proceed; backend will return 401 if unauthenticated
    }
  }

  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

/**
 * Ingest an email file (.eml / .msg) for forensic pipeline analysis.
 * Throws explicit error on failure — direct backend telemetry.
 */
export async function analyzeEmailFile(file: File): Promise<FullForensicDossier> {
  const formData = new FormData();
  formData.append('file', file);

  const response = await apiClient.post<FullForensicDossier>('/forensics/analyze?sync=true', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return response.data;
}

/**
 * Ingest raw RFC 822 email headers for forensic pipeline analysis.
 * Throws explicit error on failure — direct backend telemetry.
 */
export async function analyzeEmailHeaders(rawHeaders: string): Promise<FullForensicDossier> {
  const formData = new FormData();
  formData.append('raw_headers', rawHeaders);

  const response = await apiClient.post<FullForensicDossier>('/forensics/analyze?sync=true', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
  return response.data;
}

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
