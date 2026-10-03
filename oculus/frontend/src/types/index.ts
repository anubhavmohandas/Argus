export interface ScanResult {
  id: string;
  domain: string;
  url: string;
  status: number;
  title: string;
  server: string;
  contentLength: number;
  redirectUrl: string;
  redirectChain: string[];
  screenshot: string; // base64 PNG
  error?: string;
  interesting: boolean;
  keywords: string[];
  timestamp: string;
  durationMs: number;
  tls: boolean;
  intelligence: Intelligence;
}

export interface Intelligence {
  riskScore: number;
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
  categories: string[];
  indicators: string[];
  technologies: string[];
  ipAddress: string;
  rootDomain: string;
  hostname: string;
  brandCandidate: string;
}

export interface URLScanClusterItem {
  value: string;
  count: number;
}

export interface URLScanPivotHit {
  time: string;
  domain: string;
  ip: string;
  asn: string;
  asnName: string;
  url: string;
  title: string;
  country: string;
  screenshot: string;
  result: string;
  malicious: boolean;
  suspicious: boolean;
  brands: string[];
  relatedTags: string[];
}

export interface URLScanPivotIndicator {
  type: 'domain' | 'ip' | 'asn' | 'brand' | 'hash' | string;
  value: string;
  count: number;
  query: string;
}

export interface URLScanPivotResponse {
  indicator: string;
  type: string;
  days: number;
  query: string;
  total: number;
  results: URLScanPivotHit[];
  clusters: {
    domains: URLScanClusterItem[];
    ips: URLScanClusterItem[];
    asns: URLScanClusterItem[];
    brands: URLScanClusterItem[];
  };
  nextPivots: URLScanPivotIndicator[];
  rateLimit: {
    limit?: string;
    remaining?: string;
    reset?: string;
  };
}

export interface DeepPivotSource {
  name: string;
  status: string;
  count: number;
  error?: string;
}

export interface DeepPivotAsset {
  domain: string;
  url: string;
  title: string;
  ip: string;
  asn: string;
  asnName: string;
  country: string;
  source: string;
  screenshot: string;
  result: string;
  time: string;
  tags: string[];
  signals: string[];
}

export interface DeepPivotRecord {
  name: string;
  type: string;
  value: string;
  ttl?: number;
  source: string;
}

export interface DeepPivotCert {
  domain: string;
  issuer?: string;
  notBefore?: string;
  notAfter?: string;
  source: string;
}

export interface DeepPivotWayback {
  url: string;
  timestamp: string;
  mimeType: string;
  status: string;
  source: string;
}

export interface DeepPivotResponse {
  indicator: string;
  type: string;
  days: number;
  sources: DeepPivotSource[];
  assets: DeepPivotAsset[];
  screens: Array<{ domain: string; screenshot: string; result: string; title: string; source: string }>;
  dns: DeepPivotRecord[];
  certs: DeepPivotCert[];
  wayback: DeepPivotWayback[];
  rdap: {
    domain?: string;
    handle?: string;
    registrar?: string;
    created?: string;
    updated?: string;
    expires?: string;
    nameservers: string[];
    rawAvailable: boolean;
  };
  clusters: {
    domains: URLScanClusterItem[];
    ips: URLScanClusterItem[];
    asns: URLScanClusterItem[];
    sources: URLScanClusterItem[];
  };
  nextPivots: URLScanPivotIndicator[];
  errors: string[];
  generated: string;
}

export interface ReconTrailsSubdomain {
  domain: string;
  root: string;
  ip: string;
  asn: string;
  asnName: string;
  country: string;
  title: string;
  url: string;
  screenshot: string;
  result: string;
  sources: string[];
  signals: string[];
}

export interface ReconTrailsIPNeighbor {
  ip: string;
  asn: string;
  asnName: string;
  country: string;
  domains: string[];
  count: number;
  source: string;
}

export interface ReconTrailsResponse {
  domains: string[];
  generated: string;
  summary: {
    domainCount: number;
    subdomainCount: number;
    dnsCount: number;
    certificateCount: number;
    urlCount: number;
    screenshotCount: number;
    ipNeighborCount: number;
    riskyAssetCount: number;
  };
  sources: DeepPivotSource[];
  subdomains: ReconTrailsSubdomain[];
  dns: DeepPivotRecord[];
  certificates: DeepPivotCert[];
  rdap: DeepPivotResponse['rdap'];
  urls: DeepPivotWayback[];
  screens: DeepPivotResponse['screens'];
  assets: DeepPivotAsset[];
  ipNeighbors: ReconTrailsIPNeighbor[];
  nextPivots: URLScanPivotIndicator[];
  errors: string[];
  exports: {
    json: boolean;
    csv: boolean;
    txt: boolean;
    stix: boolean;
  };
}

export interface BrandWatchBrand {
  name: string;
  queryNames: string[];
  legitDomains: string[];
  verdictThreshold: number;
  pollMinutes: number;
}

export interface BrandLogoAsset {
  url: string;
  mimeType: string;
  domain: string;
}

export interface BrandLogoHit {
  id: string;
  uuid: string;
  brand: string;
  visibleBrand: string;
  classicBrands: string[];
  confidence: 'high' | 'review' | string;
  url: string;
  domain: string;
  apexDomain: string;
  ip: string;
  asn: string;
  asnName: string;
  country: string;
  title: string;
  screenshot: string;
  result: string;
  scanTime: string;
  liveStatus: number;
  domainAgeDays: number;
  verdictScore: number;
  urlscanMalicious: boolean;
  suspicious: boolean;
  aiLogoVerified: boolean;
  aiLogoConfidence: number;
  aiLogoReason: string;
  logoAssets: BrandLogoAsset[];
  signals: string[];
  firstSeen: string;
  lastSeen: string;
  relatedPivotQuery: string;
}

export interface BrandDomainAnalysis {
  configured: boolean;
  model: string;
  summary: string;
  risk: string;
  reasons: string[];
  pivots: string[];
  nextSteps: string[];
}

export interface BrandWatchResponse {
  configured: boolean;
  hits: BrandLogoHit[];
  brands: BrandWatchBrand[];
  lastRefresh: string;
  generatedAt: string;
  dedupeWindow: string;
  queryLog: Array<{ brand: string; mode?: string; query: string; total: number; kept: number; error?: string }>;
  rateLimit: {
    limit?: string;
    remaining?: string;
    reset?: string;
  };
}

export interface ScanJob {
  id: string;
  status: 'pending' | 'running' | 'complete' | 'error';
  total: number;
  processed: number;
  live: number;
  errors: number;
  results: ScanResult[];
  startedAt: string;
  completedAt?: string;
}

export interface ScanConfig {
  concurrency: number;
  screenWorkers: number;
  timeoutSeconds: number;
  screenshotMode: 'viewport' | 'fullpage' | 'mobile';
  maxRetries: number;
  skipScreenshots: boolean;
  onlyLive: boolean;
  followRedirects: boolean;
}

export interface FilterState {
  search: string;
  statusCodes: number[];
  interesting: boolean;
  hasScreenshot: boolean;
  minSize: number;
  maxSize: number;
  keywords: string[];
  errorOnly: boolean;
  liveOnly: boolean;
  riskLevels: Intelligence['riskLevel'][];
  minRisk: number;
  category: string;
}

export type SortField = 'domain' | 'status' | 'title' | 'contentLength' | 'durationMs' | 'timestamp' | 'riskScore';
export type SortDir = 'asc' | 'desc';

export interface ProgressEvent {
  total: number;
  processed: number;
  live: number;
  errors: number;
}
