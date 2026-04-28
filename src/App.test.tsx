import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { App } from "./App";

describe("App", () => {
  it("renders the main impact question and roadmap modules", () => {
    render(<App />);
    expect(screen.getByRole("heading", { name: "Are we impacted?" })).toBeInTheDocument();
    expect(screen.getByText("CVE Impact Discovery")).toBeInTheDocument();
    expect(screen.getByText("Vendor Incident Blast Radius")).toBeInTheDocument();
    expect(screen.getByText("Open-Source Dependency Impact")).toBeInTheDocument();
    expect(screen.getByText("Threat Campaign Relevance")).toBeInTheDocument();
    expect(screen.getByText("Autonomous Exposure Reasoning")).toBeInTheDocument();
  });
});
