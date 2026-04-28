import type { Asset, EvidenceItem, ImpactReport, OrganizationContext, PackageUsage, Severity, ThreatSignal, Vendor } from "./types";
import { isVersionAffected } from "./version";

const exploitWeight: Record<ThreatSignal["exploitStatus"], number> = { none: 0, rumored: 10, "public-poc": 18, weaponized: 26, "exploited-in-wild": 32 };

export function analyzePortfolio(threats: ThreatSignal[], org: OrganizationContext): ImpactReport[] {
  return threats.map((threat) => analyzeThreat(threat, org)).sort((a, b) => b.riskScore - a.riskScore);
}

export function analyzeThreat(threat: ThreatSignal, org: OrganizationContext): ImpactReport {
  const affectedAssets = org.assets.filter((asset) => asset.software.some((software) => threat.products.some((product) => software.name.toLowerCase().includes(product.toLowerCase())) && isVersionAffected(software.version, threat.affectedVersions)));
  const affectedVendors = threat.type === "vendor_incident" ? org.vendors.filter((vendor) => threat.products.some((product) => vendor.name.toLowerCase().includes(product.toLowerCase()))) : [];
  const affectedPackages = threat.type === "package_compromise" ? org.packages.filter((pkg) => threat.products.some((product) => pkg.name.toLowerCase() === product.toLowerCase()) && isVersionAffected(pkg.version, threat.affectedVersions)) : [];
  const relevantCampaign = threat.type === "threat_campaign" && threat.targetedIndustries.includes(org.industry);
  const evidence = buildEvidence(threat, affectedAssets, affectedVendors, affectedPackages, relevantCampaign);
  const missingData = buildMissingData(threat, affectedAssets, affectedVendors, affectedPackages);
  const riskScore = calculateRiskScore(threat, affectedAssets, affectedVendors, affectedPackages, relevantCampaign);
  const severity = toSeverity(riskScore, affectedAssets.length + affectedVendors.length + affectedPackages.length);
  const status = determineStatus(threat, affectedAssets, affectedVendors, affectedPackages, relevantCampaign, missingData);
  const confidence = Number(Math.max(0.35, Math.min(0.98, (status === "Impacted" ? 0.88 : status === "Not impacted" ? 0.72 : 0.56) + evidence.filter((item) => item.strength === "strong").length * 0.04 - missingData.length * 0.06)).toFixed(2));
  const recommendedAction = recommendAction(status, severity, affectedAssets, affectedVendors, affectedPackages);
  return { id: `report-${threat.id}`, threat, status, confidence, severity, riskScore, affectedAssets, affectedVendors, affectedPackages, evidence, missingData, recommendedAction, executiveSummary: summarize(threat, status, severity, affectedAssets, affectedVendors, affectedPackages), ticket: status === "Impacted" || severity === "Critical" ? { id: `SEC-${Math.floor(4200 + threat.id.length * 31)}`, system: "Jira", owner: affectedAssets[0]?.owner ?? affectedVendors[0]?.owner ?? affectedPackages[0]?.owner ?? "Security Operations", status: "Open" } : undefined };
}

function buildEvidence(threat: ThreatSignal, assets: Asset[], vendors: Vendor[], packages: PackageUsage[], relevantCampaign: boolean): EvidenceItem[] {
  const evidence: EvidenceItem[] = [];
  if (assets.length) evidence.push({ label: "Affected assets", detail: `${assets.length} assets run affected software versions.`, strength: "strong" });
  if (assets.some((asset) => asset.exposure === "internet-facing")) evidence.push({ label: "External exposure", detail: "At least one affected asset is internet-facing.", strength: "strong" });
  if (vendors.length) evidence.push({ label: "Vendor dependency", detail: `${vendors.length} connected vendors match this incident.`, strength: "strong" });
  if (packages.length) evidence.push({ label: "Package usage", detail: `${packages.length} package usages match compromised versions.`, strength: "strong" });
  if (threat.cisaKev) evidence.push({ label: "CISA KEV", detail: "Listed in CISA Known Exploited Vulnerabilities.", strength: "strong" });
  if (threat.exploitStatus !== "none") evidence.push({ label: "Exploit activity", detail: `Exploit status is ${threat.exploitStatus.replace(/-/g, " ")}.`, strength: "medium" });
  if (relevantCampaign) evidence.push({ label: "Industry targeting", detail: "Campaign targets the organization's industry.", strength: "medium" });
  return evidence.length ? evidence : [{ label: "No direct match", detail: "Connected inventory does not show direct exposure.", strength: "medium" }];
}

function buildMissingData(threat: ThreatSignal, assets: Asset[], vendors: Vendor[], packages: PackageUsage[]): string[] {
  const missing: string[] = [];
  if (!threat.affectedVersions?.length && ["cve", "exploit_rumor", "package_compromise"].includes(threat.type)) missing.push("Affected version range is not confirmed by source advisory.");
  if (threat.type === "cve" && !assets.length) missing.push("Validate scanner coverage for unmanaged assets.");
  if (threat.type === "vendor_incident" && !vendors.length) missing.push("Validate procurement and shadow SaaS sources.");
  if (threat.type === "package_compromise" && !packages.length) missing.push("Validate SBOM freshness and build coverage.");
  return missing;
}

function calculateRiskScore(threat: ThreatSignal, assets: Asset[], vendors: Vendor[], packages: PackageUsage[], relevantCampaign: boolean): number {
  return Math.min(100, Math.round((threat.cvss ?? 0) * 5) + Math.round((threat.epss ?? 0) * 15) + (threat.cisaKev ? 18 : 0) + exploitWeight[threat.exploitStatus] + (assets.some((asset) => asset.exposure === "internet-facing") ? 18 : 0) + (assets.some((asset) => asset.criticality === "critical") ? 12 : 0) + vendors.reduce((score, vendor) => score + (vendor.criticality === "critical" ? 12 : 7) + (vendor.ssoConnected ? 6 : 0) + (vendor.apiTokens ? 5 : 0), 0) + packages.reduce((score, pkg) => score + (pkg.deployedEnvironment === "production" ? 14 : 7), 0) + (relevantCampaign ? 14 : 0));
}

function toSeverity(score: number, affectedCount: number): Severity {
  if (affectedCount === 0 && score < 25) return "No Impact";
  if (score >= 85) return "Critical";
  if (score >= 65) return "High";
  if (score >= 40) return "Medium";
  return "Low";
}

function determineStatus(threat: ThreatSignal, assets: Asset[], vendors: Vendor[], packages: PackageUsage[], relevantCampaign: boolean, missingData: string[]): ImpactReport["status"] {
  if (assets.length || vendors.length || packages.length) return "Impacted";
  if (relevantCampaign) return "Monitoring";
  if (missingData.length && threat.exploitStatus !== "none") return "Unknown";
  if (threat.exploitStatus === "rumored") return "Possibly impacted";
  return "Not impacted";
}

function recommendAction(status: ImpactReport["status"], severity: Severity, assets: Asset[], vendors: Vendor[], packages: PackageUsage[]): string {
  if (status === "Not impacted") return "Document non-impact determination and continue monitoring exploit activity.";
  if (packages.length) return "Rebuild affected services, roll back compromised packages, and rotate secrets for production deployments.";
  if (vendors.length) return "Request vendor incident details, review SSO/OAuth grants, rotate API tokens, and notify business owners.";
  if (assets.some((asset) => asset.exposure === "internet-facing")) return "Patch or isolate internet-facing assets first, then run detection queries for exploitation indicators.";
  if (severity === "Critical") return "Open incident bridge, assign remediation owner, and validate compensating controls immediately.";
  return "Validate inventory coverage, monitor advisories, and prepare remediation ticket if exposure is confirmed.";
}

function summarize(threat: ThreatSignal, status: ImpactReport["status"], severity: Severity, assets: Asset[], vendors: Vendor[], packages: PackageUsage[]): string {
  const impacted = assets.length + vendors.length + packages.length;
  if (status === "Impacted") return `${threat.title} impacts ${impacted} connected environment items. Severity is ${severity}; remediation should start with exposed or production systems.`;
  if (status === "Monitoring") return `${threat.title} is relevant to the organization profile, but direct technical exposure is not confirmed.`;
  if (status === "Not impacted") return `${threat.title} has no confirmed exposure in connected inventory based on current evidence.`;
  return `${threat.title} requires additional validation before impact can be confirmed.`;
}
