# Mythos Discover

Mythos Discover is a production-oriented frontend and reasoning-engine scaffold for answering the CISO question: **Are we impacted?**

It connects external threat signals such as CVEs, CISA KEV, exploit rumors, package compromises, vendor incidents, and threat campaigns to internal context such as assets, software, package usage, vendors, identity connections, controls, owners, and tickets.

## Implemented Product Areas

- CVE impact discovery
- Vendor incident blast-radius analysis
- Open-source package compromise discovery
- Threat campaign relevance scoring
- Exposure graph
- Evidence-backed impact reports
- Remediation workflow and ticketing surfaces
- Executive brief generation
- Integration architecture for scanners, cloud inventory, SBOM, SIEM, EDR, identity, and ticketing

## Run Locally

```bash
npm install
npm run dev
```

## Validate

```bash
npm run typecheck
npm run test
npm run build
```

## Architecture

The current build uses local seeded data through typed adapters. Production connectors should implement the same interfaces in `src/domain/adapters.ts`.

```text
External signals -> adapters -> exposure graph -> impact engine -> reports/workflows -> UI
```

## Deployment

Build static assets with:

```bash
npm run build
```

Or build the included container:

```bash
docker build -t mythos-discover .
docker run -p 8080:80 mythos-discover
```
