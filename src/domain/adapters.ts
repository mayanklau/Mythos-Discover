import type { OrganizationContext, ThreatSignal } from "./types";

export interface ThreatSignalAdapter { listSignals(): Promise<ThreatSignal[]>; }
export interface OrganizationContextAdapter { getContext(): Promise<OrganizationContext>; }
export interface TicketingAdapter { createRemediationTicket(input: { title: string; owner: string; severity: string; evidence: string[] }): Promise<{ id: string; url: string }>; }
export interface NotificationAdapter { sendCriticalAlert(input: { channel: string; title: string; message: string }): Promise<void>; }
