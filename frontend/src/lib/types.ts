export interface EmailDossier {
  id: string;
  sha256_hash: string;
  md5_hash: string;
  file_name: string;
  file_size_bytes: number;
  raw_storage_path?: string;
  rfc822_msg_id?: string;
  subject: string;
  sender_raw?: string;
  sender_email: string;
  sender_display?: string;
  return_path?: string;
  reply_to?: string;
  recipient_list: string[];
  date_header?: string;
  body_plain?: string;
  body_html?: string;
  simhash_body?: string;
  ingested_at: string;
}

export interface HeaderHop {
  id: string;
  email_id: string;
  hop_order: number;
  by_mta?: string;
  from_mta?: string;
  hop_ip?: string;
  is_private_ip: boolean;
  is_reliable: boolean;
  protocol?: string;
  hop_timestamp?: string;
  delay_seconds: number;
  geo_country?: string;
  geo_city?: string;
  geo_lat?: number;
  geo_lon?: number;
  asn_number?: number;
  asn_org?: string;
  node_type: string; // ORIGINATING, RELAY, EDGE_GATEWAY, INTERNAL, TOR_EXIT, DATACENTER_PROXY
  is_tor: boolean;
  is_vpn: boolean;
  is_datacenter: boolean;
}

export interface ForensicAnalysis {
  id: string;
  email_id: string;
  spf_status: string; // PASS, FAIL, SOFTFAIL, NONE
  spf_domain?: string;
  dkim_status: string; // PASS, FAIL, NONE
  dkim_selector?: string;
  dkim_domain?: string;
  dmarc_status: string; // PASS, FAIL, NONE
  dmarc_policy?: string;
  dmarc_alignment_spf: boolean;
  dmarc_alignment_dkim: boolean;
  display_spoof_flag: boolean;
  lookalike_flag: boolean;
  homograph_flag: boolean;
  threat_score: number;
  verdict: 'BENIGN' | 'SUSPICIOUS' | 'PHISHING' | 'BEC' | 'MALICIOUS';
  score_breakdown: {
    final_score?: number;
    verdict?: string;
    subscores?: {
      auth: number;
      header: number;
      nlp: number;
      url: number;
      osint: number;
      attachment: number;
    };
    critical_override_applied?: boolean;
    reasons?: string[];
  };
}

export interface ThreatIndicator {
  id: string;
  email_id: string;
  ioc_type: 'URL' | 'DOMAIN' | 'IP' | 'HASH' | 'EMAIL_ADDR';
  ioc_value: string;
  context?: string;
  is_defanged: boolean;
  domain_age_days?: number;
  registrar?: string;
  reputation_score?: number;
  metadata?: Record<string, any>;
}

export interface AuditLog {
  id: string;
  email_id?: string;
  action_performed: string;
  actor: string;
  recorded_at: string;
  evidence_sha256: string;
  integrity_check: boolean;
  hmac_signature: string;
  details: Record<string, any>;
}

export interface CampaignAssociation {
  campaign_id: string;
  name: string;
  cluster_type?: string;
  similarity_score: number;
  matched_criteria: Record<string, any>;
}

export interface FullForensicDossier {
  email: EmailDossier;
  forensic_analysis: ForensicAnalysis;
  header_hops: HeaderHop[];
  threat_indicators: ThreatIndicator[];
  campaigns: CampaignAssociation[];
  audit_logs: AuditLog[];
}

export interface GraphNode {
  id: string;
  label: string;
  type: 'CAMPAIGN' | 'EMAIL' | 'INFRASTRUCTURE_IP' | 'IOC';
  metadata: Record<string, any>;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  relationship: string;
  metadata?: Record<string, any>;
}

export interface CampaignGraphData {
  graph: {
    total_nodes: number;
    total_edges: number;
    nodes: GraphNode[];
    edges: GraphEdge[];
  };
}

