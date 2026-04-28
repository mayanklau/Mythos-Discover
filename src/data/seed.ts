import type { IntegrationHealth, OrganizationContext, ThreatSignal } from "../domain/types";

export const organization: OrganizationContext = {
  name: "Acme Financial Services",
  industry: "financial-services",
  assets: [
    { id: "asset-1", hostname: "vpn-edge-01.acme.com", businessService: "Remote Access", owner: "Infrastructure Security", criticality: "critical", exposure: "internet-facing", software: [{ name: "ExampleVPN Gateway", version: "4.2.1" }], controls: ["WAF monitoring", "EDR"], dataSensitivity: "restricted" },
    { id: "asset-2", hostname: "payments-api-prod", businessService: "Payments API", owner: "Payments Platform", criticality: "critical", exposure: "private-cloud", software: [{ name: "Apache Struts", version: "2.5.29" }], controls: ["Runtime EDR", "Network segmentation"], dataSensitivity: "restricted" },
    { id: "asset-3", hostname: "citrix-gw-02.acme.com", businessService: "Partner Portal", owner: "Enterprise Apps", criticality: "high", exposure: "internet-facing", software: [{ name: "Citrix ADC", version: "13.1.49" }], controls: ["Geo restrictions"], dataSensitivity: "confidential" },
  ],
  vendors: [
    { id: "vendor-1", name: "Northstar CRM", owner: "Revenue Operations", dataShared: ["customer contacts", "deal records"], ssoConnected: true, apiTokens: true, criticality: "critical" },
    { id: "vendor-2", name: "ClearLedger Payroll", owner: "People Operations", dataShared: ["employee identity", "payroll records"], ssoConnected: true, apiTokens: false, criticality: "high" },
  ],
  packages: [
    { id: "pkg-1", ecosystem: "npm", name: "fast-json-pipe", version: "3.1.4", repository: "github.com/acme/payments-ui", deployedEnvironment: "production", owner: "Payments Platform" },
    { id: "pkg-2", ecosystem: "pypi", name: "yaml-safe-load", version: "1.8.2", repository: "github.com/acme/risk-models", deployedEnvironment: "staging", owner: "Risk Analytics" },
  ],
};

export const threatSignals: ThreatSignal[] = [
  { id: "cve-examplevpn-rce", type: "cve", title: "CVE-2026-18442 ExampleVPN Gateway pre-auth RCE", source: "Vendor advisory + CISA KEV", summary: "Critical pre-auth remote code execution in ExampleVPN Gateway appliances.", products: ["ExampleVPN Gateway"], affectedVersions: ["4.0.0-4.2.3"], cvss: 9.8, epss: 0.91, cisaKev: true, exploitStatus: "exploited-in-wild", targetedIndustries: ["financial-services", "healthcare"], indicators: ["198.51.100.44", "/vpn/session/diag"] },
  { id: "vendor-northstar-breach", type: "vendor_incident", title: "Northstar CRM reports token exposure", source: "Vendor security notice", summary: "Vendor reports support-system tokens may have been accessed.", products: ["Northstar CRM"], affectedVersions: [], cvss: 0, epss: 0, cisaKev: false, exploitStatus: "none", targetedIndustries: ["financial-services", "retail"], indicators: ["northstar-support-token"] },
  { id: "npm-fast-json-pipe", type: "package_compromise", title: "Malicious npm package fast-json-pipe version 3.1.x", source: "npm advisory + GitHub Security Advisory", summary: "Maintainer compromise inserted credential-stealing code.", products: ["fast-json-pipe"], affectedVersions: ["3.1.x"], cvss: 8.1, epss: 0.63, cisaKev: false, exploitStatus: "weaponized", targetedIndustries: ["technology", "financial-services"], indicators: ["fast-json-pipe-3.1.4.tgz"] },
  { id: "campaign-citrix-ransomware", type: "threat_campaign", title: "Ransomware crews targeting financial services Citrix gateways", source: "Threat intel feed", summary: "Actors are targeting financial services organizations with exposed Citrix gateways.", products: ["Citrix ADC"], affectedVersions: ["13.1.0-13.1.50"], cvss: 8.6, epss: 0.77, cisaKev: false, exploitStatus: "weaponized", targetedIndustries: ["financial-services"], indicators: ["203.0.113.91"] },
  { id: "rumor-struts-zero-day", type: "exploit_rumor", title: "Unverified Apache Struts zero-day rumor", source: "Telegram actor channel", summary: "Low-confidence claim that a Struts bypass exploit is being sold privately.", products: ["Apache Struts"], affectedVersions: [], cvss: 0, epss: 0.21, cisaKev: false, exploitStatus: "rumored", targetedIndustries: ["financial-services", "government"], indicators: ["actor-claim-908"] },
];

export const integrations: IntegrationHealth[] = [
  { name: "Tenable", category: "scanner", status: "mocked", lastSync: "2m ago" },
  { name: "Wiz", category: "cloud", status: "mocked", lastSync: "4m ago" },
  { name: "CycloneDX SBOM", category: "sbom", status: "connected", lastSync: "8m ago" },
  { name: "Splunk", category: "siem", status: "mocked", lastSync: "13m ago" },
  { name: "Okta", category: "identity", status: "mocked", lastSync: "17m ago" },
  { name: "Jira", category: "ticketing", status: "connected", lastSync: "1m ago" },
  { name: "CISA KEV + EPSS", category: "threat-intel", status: "connected", lastSync: "now" },
];
