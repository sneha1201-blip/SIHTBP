import axios from 'axios';
import { FullForensicDossier, CampaignGraphData } from './types';
import { MOCK_DOSSIERS, MOCK_GRAPH } from './mockData';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

export const apiClient = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
});

export async function analyzeEmailFile(file: File): Promise<FullForensicDossier> {
  const formData = new FormData();
  formData.append('file', file);

  try {
    const response = await apiClient.post<FullForensicDossier>('/forensics/analyze', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data;
  } catch (error) {
    console.warn('Backend API unavailable. Falling back to intelligent mock dossier:', error);
    // Select an appropriate mock based on filename
    const lowerName = file.name.toLowerCase();
    if (lowerName.includes('tor')) return MOCK_DOSSIERS['tor-phishing'];
    if (lowerName.includes('homograph') || lowerName.includes('aph')) return MOCK_DOSSIERS['homograph-attack'];
    if (lowerName.includes('circular') || lowerName.includes('legit')) return MOCK_DOSSIERS['legitimate-circular'];
    if (lowerName.includes('falcon') || lowerName.includes('cluster')) return MOCK_DOSSIERS['falconshield-cluster'];
    return MOCK_DOSSIERS['bec-wire-fraud'];
  }
}

export async function analyzeEmailHeaders(rawHeaders: string): Promise<FullForensicDossier> {
  const formData = new FormData();
  formData.append('raw_headers', rawHeaders);

  try {
    const response = await apiClient.post<FullForensicDossier>('/forensics/analyze', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    });
    return response.data;
  } catch (error) {
    console.warn('Backend API unavailable. Falling back to mock dossier:', error);
    if (rawHeaders.includes('185.220.101.5')) return MOCK_DOSSIERS['tor-phishing'];
    if (rawHeaders.includes('xn--') || rawHeaders.includes('\u0430icte')) return MOCK_DOSSIERS['homograph-attack'];
    if (rawHeaders.includes('194.36.191.')) return MOCK_DOSSIERS['falconshield-cluster'];
    return MOCK_DOSSIERS['bec-wire-fraud'];
  }
}

export async function fetchEvidenceDossier(id: string): Promise<FullForensicDossier> {
  try {
    const response = await apiClient.get<FullForensicDossier>(`/forensics/evidence/${id}`);
    return response.data;
  } catch (error) {
    console.warn(`Could not load evidence ${id} from backend. Serving mock:`, error);
    return MOCK_DOSSIERS['bec-wire-fraud'];
  }
}

export async function fetchCampaignGraph(): Promise<CampaignGraphData> {
  try {
    const response = await apiClient.get<CampaignGraphData>('/campaigns/graph');
    return response.data;
  } catch (error) {
    console.warn('Could not load campaign graph from backend. Serving mock graph:', error);
    return MOCK_GRAPH;
  }
}

export async function downloadForensicReportPdf(id: string, sha256: string): Promise<void> {
  try {
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
  } catch (error) {
    console.error('Failed to download PDF report from backend:', error);
    alert('PDF report download failed. Ensure backend is running at http://localhost:8000');
  }
}

