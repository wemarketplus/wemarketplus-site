import type { ComponentType } from 'react';
import type { ISODateString } from '@/shared/types';

// Owner portal — the "founder dashboard" the site exposes at /owner portal.
// All shapes are local to this module since none of these entities are
// shared with the rest of the app.

export type OwnerScreen =
  | 'dashboard'
  | 'revenue'
  | 'customers'
  | 'pipeline'
  | 'visitors'
  | 'marketing'
  | 'churn'
  | 'usage'
  | 'insights'
  | 'communication'
  | 'security'
  | 'admin-controls';

export interface OwnerNavItem {
  to: string;
  screen: OwnerScreen;
  label: string;
  icon: ComponentType<{ className?: string }>;
  badge?: string;
}

export interface OwnerKPI {
  id: string;
  label: string;
  value: string;
  delta?: string;
  positive?: boolean;
}

export interface OwnerCustomer {
  id: string;
  organization: string;
  plan: string;
  mrr: number;
  status: 'active' | 'past_due' | 'churned';
  joinedAt: ISODateString;
  healthScore: number;
}

export interface OwnerRevenueMonth {
  month: string;
  mrr: number;
  arr: number;
  newCustomers: number;
  churned: number;
}

export interface OwnerPipelineDeal {
  id: string;
  prospect: string;
  stage: 'demo' | 'pilot' | 'contract' | 'won' | 'lost';
  estimatedMrr: number;
  closeBy: ISODateString;
  owner: string;
}

export interface OwnerVisitor {
  id: string;
  source: string;
  landingPage: string;
  sessionLengthSec: number;
  visitedAt: ISODateString;
  converted: boolean;
}

export interface OwnerChurnRow {
  id: string;
  organization: string;
  reason: string;
  daysIdle: number;
  recoveryAttempt: 'none' | 'email_sent' | 'call_scheduled' | 'recovered';
}

export interface OwnerUsageRow {
  id: string;
  organization: string;
  seatsUsed: number;
  seatsBilled: number;
  apiCallsLast30d: number;
  lastActiveAt: ISODateString;
}

export interface OwnerInsight {
  id: string;
  title: string;
  summary: string;
  recommendation: string;
  severity: 'info' | 'opportunity' | 'risk';
}

export interface OwnerCommunication {
  id: string;
  channel: 'email' | 'call' | 'in_app';
  with: string;
  topic: string;
  occurredAt: ISODateString;
}

export interface OwnerAuditEntry {
  id: string;
  actor: string;
  action: string;
  target: string;
  occurredAt: ISODateString;
  ipAddress: string;
}

export interface OwnerPortalUiState {
  // Reserved for future UI prefs (chart range, table density).
  _placeholder: true;
}
