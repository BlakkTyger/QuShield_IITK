// ─── QuShield API Types ───────────────────────────────────────

// Auth
export interface UserCreate {
  email: string;
  password: string;
  full_name: string;
}

export interface Token {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface UserResponse {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
  role: string;
  created_at: string;
}

// Scans
export interface ScanTrigger {
  domain: string;
  max_assets?: number;
  skip_discovery?: boolean;
  targets?: string[];
}

export interface ScanResponse {
  id: string;
  domain: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  assets_discovered: number;
  assets_scanned: number;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
}

export interface ScanStatus {
  id: string;
  status: string;
  progress: number | null;
  assets_discovered: number;
  assets_scanned: number;
  started_at: string | null;
  error_message: string | null;
}

export interface ScanListResponse {
  items: ScanResponse[];
  total: number;
  page: number;
  size: number;
}

// Assets
export interface Asset {
  id: string;
  fqdn: string;
  port: number;
  ipv4_address: string | null;
  ipv6_address: string | null;
  owner: string | null;
  asset_type: string | null;
  quantum_safety: string | null;
  cert_tier: string | null;
  risk_level: string | null;
  hndl_score: number | null;
  hndl_label: string | null;
  status: string | null;
  discovery_source: string | null;
  detection_date: string | null;
  scan_success: boolean;
}

export interface AssetDetail extends Asset {
  scan_error: string | null;
  recommended_action: string | null;
  certificates: CertificateResponse[];
  crypto_security: CryptoSecurityResponse[];
}

export interface AssetListResponse {
  items: Asset[];
  total: number;
  page: number;
  size: number;
}

export interface CertificateResponse {
  id: string;
  subject_cn: string | null;
  issuer_cn: string | null;
  certificate_authority: string | null;
  valid_from: string | null;
  valid_until: string | null;
  days_until_expiry: number | null;
  is_expired: boolean;
  key_algorithm: string | null;
  key_size: number | null;
  signature_algorithm: string | null;
  sha256_fingerprint: string | null;
  san_count: number;
}

export interface CryptoSecurityResponse {
  id: string;
  tls_version: string | null;
  cipher_suite: string | null;
  key_exchange_algorithm: string | null;
  encryption_algorithm: string | null;
  key_length: number | null;
  forward_secrecy: boolean;
  pqc_algorithm: string | null;
  quantum_safety: string | null;
}

// Dashboard
export interface AssetCounts {
  total_assets: number;
  public_web_apps: number;
  apis: number;
  servers: number;
  gateways: number;
  cdns: number;
}

export interface QuantumSafetyCounts {
  quantum_safe: number;
  hybrid: number;
  vulnerable: number;
  critical: number;
}

export interface CertificationCounts {
  platinum: number;
  gold: number;
  silver: number;
  bronze: number;
}

export interface CertExpiryCounts {
  expired: number;
  expiring_30d: number;
  expiring_60d: number;
  expiring_90d: number;
}

export interface IPBreakdown {
  ipv4_count: number;
  ipv6_count: number;
  ipv4_percent: number;
  ipv6_percent: number;
}

export interface DashboardMetrics {
  asset_counts: AssetCounts;
  quantum_safety: QuantumSafetyCounts;
  certifications: CertificationCounts;
  cert_expiry: CertExpiryCounts;
  ip_breakdown: IPBreakdown;
  enterprise_score: number | null;
  rating_category: string | null;
  average_hndl_score: number | null;
  last_scan_id: string | null;
  last_scan_domain: string | null;
}

// Risk Distribution
export interface RiskDistributionItem {
  label: string;
  count: number;
  percentage: number;
}

export interface HighRiskAsset {
  id: string;
  fqdn: string;
  risk_level: string;
  hndl_score: number | null;
  quantum_safety: string | null;
}

export interface ExpiringCert {
  id: string;
  asset_fqdn: string;
  subject_cn: string;
  valid_until: string;
  days_until_expiry: number;
}

export interface RiskDistribution {
  risk_levels: RiskDistributionItem[];
  asset_types: RiskDistributionItem[];
  quantum_safety: RiskDistributionItem[];
  high_risk_assets: HighRiskAsset[];
  expiring_certs: ExpiringCert[];
}

// Discovery
export interface DiscoverySummary {
  domains_count: number;
  ssl_certs_count: number;
  ip_subnets_count: number;
  software_count: number;
  cloud_assets: number;
  iot_devices: number;
  login_forms: number;
}

export interface DomainItem {
  id: string;
  fqdn: string;
  detection_date: string;
  status: string;
  ipv4_address: string | null;
  ipv6_address: string | null;
  asset_type: string | null;
  risk_level: string | null;
}

export interface DomainList {
  items: DomainItem[];
  total: number;
}

export interface GraphNode {
  id: string;
  type: string;
  label: string;
  properties: Record<string, unknown>;
}

export interface GraphEdge {
  source: string;
  target: string;
  relationship: string;
  properties: Record<string, unknown>;
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

// CBOM
export interface CipherUsage {
  cipher: string;
  count: number;
  percentage: number;
}

export interface KeyLengthDist {
  key_length: number;
  count: number;
  percentage: number;
}

export interface CADistribution {
  ca_name: string;
  count: number;
  percentage: number;
}

export interface TLSVersionDist {
  version: string;
  count: number;
  percentage: number;
}

export interface CBOMMetrics {
  total_applications: number;
  active_certificates: number;
  weak_crypto_count: number;
  certificate_issues: number;
  cipher_usage: CipherUsage[];
  key_length_distribution: KeyLengthDist[];
  top_cas: CADistribution[];
  tls_version_distribution: TLSVersionDist[];
}

// Posture
export interface ClassificationGrade {
  grade: string;
  count: number;
  percentage: number;
}

export interface Recommendation {
  id: string;
  priority: string;
  category: string;
  title: string;
  description: string;
  affected_assets: number;
  action: string;
}

export interface PostureSummary {
  pqc_adoption_progress: number;
  compliance_status: string;
  migration_priority: string;
  classifications: ClassificationGrade[];
  elite_count: number;
  standard_count: number;
  legacy_count: number;
  critical_count: number;
}

export interface RecommendationList {
  items: Recommendation[];
  total: number;
}

export interface PQCCertificate {
  id: string;
  asset_id: string;
  asset_fqdn: string;
  cert_tier: string;
  certification_level: string;
  score: number;
  issued_at: string;
  valid_until: string;
  signature_algorithm: string;
}

export interface PQCCertificateList {
  items: PQCCertificate[];
  total: number;
}

// Rating
export interface EnterpriseRating {
  enterprise_score: number;
  category: string;
  breakdown: Record<string, { weight: number; score: number }>;
}

export interface AssetRatingItem {
  id: string;
  fqdn: string;
  url: string;
  score: number;
  category: string;
  hndl_score: number | null;
  quantum_safety: string | null;
}

export interface AssetRating {
  items: AssetRatingItem[];
  total: number;
  average_score: number;
}

// Reports
export interface ReportGenerate {
  scan_id: string;
  report_type: string;
  file_format: string;
}

export interface ReportSchedule {
  report_type: string;
  frequency: string;
  cron_expression?: string;
  selected_scans?: string[];
  included_sections?: string[];
  delivery_email?: string;
}

export interface ReportResponse {
  id: string;
  scan_id: string;
  report_type: string;
  file_format: string;
  file_path: string;
  generated_at: string;
  expires_at: string;
}

export interface ReportListResponse {
  items: ReportResponse[];
  total: number;
}

export interface ScheduledReportResponse {
  id: string;
  report_type: string;
  frequency: string;
  next_run_at: string;
  is_active: boolean;
}
