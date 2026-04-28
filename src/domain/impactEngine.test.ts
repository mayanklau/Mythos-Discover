import { describe, expect, it } from "vitest";
import { organization, threatSignals } from "../data/seed";
import { analyzePortfolio, analyzeThreat } from "./impactEngine";

describe("impact engine", () => {
  it("classifies an exposed vulnerable VPN as impacted and critical", () => {
    const report = analyzeThreat(threatSignals[0], organization);
    expect(report.status).toBe("Impacted");
    expect(report.severity).toBe("Critical");
    expect(report.affectedAssets.map((asset) => asset.hostname)).toContain("vpn-edge-01.acme.com");
  });

  it("maps package compromise to production package usage", () => {
    const report = analyzeThreat(threatSignals[2], organization);
    expect(report.status).toBe("Impacted");
    expect(report.affectedPackages).toHaveLength(1);
    expect(report.recommendedAction).toContain("Rebuild");
  });

  it("sorts portfolio by highest risk first", () => {
    const reports = analyzePortfolio(threatSignals, organization);
    expect(reports[0].riskScore).toBeGreaterThanOrEqual(reports[1].riskScore);
  });
});
