export type ThreatType = "cve" | "vendor_incident" | "package_compromise" | "threat_campaign" | "exploit_rumor";
export type ImpactStatus = "Impacted" | "Possibly impacted" | "Not impacted" | "Unknown" | "Monitoring";
export type Severity = "Critical" | "High" | "Medium" | "Low" | "No Impact";
export type AssetExposure = "internet-facing" | "internal" | "private-cloud" | "third-party";

export interface ThreatSignal {
  id: string;
  type: ThreatType;
  title: string;
  source: string;
  summary: string;
  products: string[];
  affectedVersions?: string[];
  cvss?: number;
  epss?: number;
  cisaKev?: boolean;
  exploitStatus: "none" | "rumored" | "public-poc" | "weaponized" | "exploited-in-wild";
  targetedIndustries: string[];
  indicators: string[];
}

export interface Asset {
  id: string;
  hostname: string;
  businessService: string;
  owner: string;
  criticality: "critical" | "high" | "medium" | "low";
  exposure: AssetExposure;
  software: Array<{ name: string; version: string }>;
  controls: string[];
  dataSensitivity: "restricted" | "confidential" | "internal" | "public";
}

export interface Vendor {
  id: string;
  name: string;
  owner: string;
  dataShared: string[];
  ssoConnected: boolean;
  apiTokens: boolean;
  criticality: "critical" | "high" | "medium" | "low";
}

export interface PackageUsage {
  id: string;
  ecosystem: "npm" | "pypi" | "maven" | "go" | "rubygems";
  name: string;
  version: string;
  repository: string;
  deployedEnvironment: "production" | "staging" | "development";
  owner: string;
}

export interface OrganizationContext {
  name: string;
  industry: string;
  assets: Asset[];
  vendors: Vendor[];
  packages: PackageUsage[];
}

export interface EvidenceItem { label: string; detail: string; strength: "strong" | "medium" | "weak"; }

export interface ImpactReport {
  id: string;
  threat: ThreatSignal;
  status: ImpactStatus;
  confidence: number;
  severity: Severity;
  riskScore: number;
  affectedAssets: Asset[];
  affectedVendors: Vendor[];
  affectedPackages: PackageUsage[];
  evidence: EvidenceItem[];
  missingData: string[];
  recommendedAction: string;
  executiveSummary: string;
  ticket?: { id: string; system: "Jira" | "ServiceNow"; owner: string; status: "Open" | "In Progress" | "Blocked" | "Resolved" };
}

export interface IntegrationHealth {
  name: string;
  category: "scanner" | "cloud" | "sbom" | "siem" | "identity" | "ticketing" | "threat-intel";
  status: "connected" | "degraded" | "mocked";
  lastSync: string;
}
