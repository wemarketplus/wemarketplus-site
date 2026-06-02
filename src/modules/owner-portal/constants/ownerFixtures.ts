import type {
  OwnerAuditEntry,
  OwnerChurnRow,
  OwnerCommunication,
  OwnerCustomer,
  OwnerInsight,
  OwnerKPI,
  OwnerMarketingChannel,
  OwnerPipelineDeal,
  OwnerRevenueMonth,
  OwnerUsageRow,
  OwnerVisitor,
} from '../types/ownerPortalTypes';

// Owner-portal-only fixtures. Lives inside the module (not shared/fixtures)
// because nothing else consumes these shapes. TODO(backend): replace each
// consumer with a real RTK Query call when /owner/* endpoints ship.

export const OWNER_KPIS: readonly OwnerKPI[] = [
  { id: 'mrr', label: 'MRR', value: '$184,200', delta: '+8.4% MoM', positive: true },
  { id: 'arr', label: 'ARR', value: '$2.21M', delta: '+11.0% YoY', positive: true },
  { id: 'customers', label: 'Active customers', value: '218', delta: '+9 this month', positive: true },
  { id: 'churn', label: 'Net churn', value: '0.9%', delta: '-0.3pp', positive: true },
];

export const OWNER_MARKETING_CHANNELS: readonly OwnerMarketingChannel[] = [
  { id: 'google', label: 'Google Ads', spend: 8400, leads: 142, conversion: 0.18 },
  { id: 'linkedin', label: 'LinkedIn', spend: 5200, leads: 76, conversion: 0.11 },
  { id: 'partners', label: 'Partner referrals', spend: 0, leads: 38, conversion: 0.34 },
  { id: 'content', label: 'Content & SEO', spend: 1800, leads: 121, conversion: 0.09 },
];

export const OWNER_REVENUE_MONTHS: readonly OwnerRevenueMonth[] = [
  { month: 'Jan', mrr: 142000, arr: 1704000, newCustomers: 14, churned: 2 },
  { month: 'Feb', mrr: 151000, arr: 1812000, newCustomers: 13, churned: 1 },
  { month: 'Mar', mrr: 158000, arr: 1896000, newCustomers: 11, churned: 3 },
  { month: 'Apr', mrr: 168000, arr: 2016000, newCustomers: 16, churned: 2 },
  { month: 'May', mrr: 184200, arr: 2210400, newCustomers: 18, churned: 1 },
];

export const OWNER_CUSTOMERS: readonly OwnerCustomer[] = [
  {
    id: 'c-001',
    organization: 'Bay Area Hospice Group',
    plan: 'HospiceLink Pro',
    mrr: 1290,
    status: 'active',
    joinedAt: '2025-03-12T00:00:00Z',
    healthScore: 0.86,
  },
  {
    id: 'c-002',
    organization: 'Sequoia Senior Living',
    plan: 'CommunityLink Gold',
    mrr: 3450,
    status: 'active',
    joinedAt: '2025-01-04T00:00:00Z',
    healthScore: 0.91,
  },
  {
    id: 'c-003',
    organization: 'Northstar Hospice',
    plan: 'HospiceLink Gold',
    mrr: 2890,
    status: 'past_due',
    joinedAt: '2024-09-21T00:00:00Z',
    healthScore: 0.48,
  },
  {
    id: 'c-004',
    organization: 'Pinecrest Care',
    plan: 'HospiceLink Pro',
    mrr: 1290,
    status: 'active',
    joinedAt: '2025-04-29T00:00:00Z',
    healthScore: 0.72,
  },
  {
    id: 'c-005',
    organization: 'Cypress Communities',
    plan: 'CommunityLink Pro',
    mrr: 1890,
    status: 'churned',
    joinedAt: '2024-06-12T00:00:00Z',
    healthScore: 0.12,
  },
];

export const OWNER_PIPELINE: readonly OwnerPipelineDeal[] = [
  {
    id: 'd-001',
    prospect: 'Lakeside Senior Care',
    stage: 'demo',
    estimatedMrr: 1890,
    closeBy: '2026-06-12T00:00:00Z',
    owner: 'Avery Cole',
  },
  {
    id: 'd-002',
    prospect: 'Cascade Hospice',
    stage: 'pilot',
    estimatedMrr: 2890,
    closeBy: '2026-06-05T00:00:00Z',
    owner: 'Jordan Reese',
  },
  {
    id: 'd-003',
    prospect: 'Magnolia Place',
    stage: 'contract',
    estimatedMrr: 3450,
    closeBy: '2026-05-29T00:00:00Z',
    owner: 'Sam Brennan',
  },
  {
    id: 'd-004',
    prospect: 'Trinity Pacific',
    stage: 'won',
    estimatedMrr: 1290,
    closeBy: '2026-05-22T00:00:00Z',
    owner: 'Avery Cole',
  },
  {
    id: 'd-005',
    prospect: 'Heritage Hospice',
    stage: 'lost',
    estimatedMrr: 1290,
    closeBy: '2026-05-18T00:00:00Z',
    owner: 'Jordan Reese',
  },
];

export const OWNER_VISITORS: readonly OwnerVisitor[] = [
  {
    id: 'v-001',
    source: 'Google ad — “hospice CRM”',
    landingPage: '/hospicelink-pro',
    sessionLengthSec: 312,
    visitedAt: '2026-05-24T17:22:00Z',
    converted: true,
  },
  {
    id: 'v-002',
    source: 'LinkedIn',
    landingPage: '/',
    sessionLengthSec: 94,
    visitedAt: '2026-05-24T16:08:00Z',
    converted: false,
  },
  {
    id: 'v-003',
    source: 'Referral — heeg.co',
    landingPage: '/communitylink-gold',
    sessionLengthSec: 218,
    visitedAt: '2026-05-24T14:51:00Z',
    converted: false,
  },
  {
    id: 'v-004',
    source: 'Direct',
    landingPage: '/pricing',
    sessionLengthSec: 460,
    visitedAt: '2026-05-24T11:14:00Z',
    converted: true,
  },
];

export const OWNER_CHURN: readonly OwnerChurnRow[] = [
  {
    id: 'cr-001',
    organization: 'Northstar Hospice',
    reason: 'Payment failed twice',
    daysIdle: 12,
    recoveryAttempt: 'call_scheduled',
  },
  {
    id: 'cr-002',
    organization: 'Maplewood Living',
    reason: 'Login activity down 70%',
    daysIdle: 21,
    recoveryAttempt: 'email_sent',
  },
  {
    id: 'cr-003',
    organization: 'Bridgewater Hospice',
    reason: 'Champion left the org',
    daysIdle: 9,
    recoveryAttempt: 'none',
  },
];

export const OWNER_USAGE: readonly OwnerUsageRow[] = [
  {
    id: 'u-001',
    organization: 'Bay Area Hospice Group',
    seatsUsed: 11,
    seatsBilled: 15,
    apiCallsLast30d: 24300,
    lastActiveAt: '2026-05-24T17:55:00Z',
  },
  {
    id: 'u-002',
    organization: 'Sequoia Senior Living',
    seatsUsed: 28,
    seatsBilled: 30,
    apiCallsLast30d: 87200,
    lastActiveAt: '2026-05-24T17:48:00Z',
  },
  {
    id: 'u-003',
    organization: 'Pinecrest Care',
    seatsUsed: 6,
    seatsBilled: 10,
    apiCallsLast30d: 8400,
    lastActiveAt: '2026-05-23T22:11:00Z',
  },
];

export const OWNER_INSIGHTS: readonly OwnerInsight[] = [
  {
    id: 'ai-001',
    title: 'Pro → Gold upsell signal',
    summary:
      'Bay Area Hospice Group has hit 92% of their messaging quota three months in a row.',
    recommendation:
      'Send a personalized Gold-tier offer with a 30-day money-back guarantee.',
    severity: 'opportunity',
  },
  {
    id: 'ai-002',
    title: 'Cohort retention risk',
    summary:
      'Q3 2024 cohort retention dropped to 78% — 6 points below historical baseline.',
    recommendation:
      'Run a structured outreach to the 4 highest-MRR accounts in the cohort.',
    severity: 'risk',
  },
  {
    id: 'ai-003',
    title: 'Onboarding velocity improving',
    summary:
      'Median time-to-first-referral dropped from 6.1 days to 3.4 days after the new wizard.',
    recommendation: 'Continue investing in the guided onboarding flow.',
    severity: 'info',
  },
];

export const OWNER_COMMUNICATIONS: readonly OwnerCommunication[] = [
  {
    id: 'cm-001',
    channel: 'email',
    with: 'Pinecrest Care — Bilal Z.',
    topic: 'Quarterly review — sent agenda',
    occurredAt: '2026-05-24T15:30:00Z',
  },
  {
    id: 'cm-002',
    channel: 'call',
    with: 'Northstar Hospice — Lana D.',
    topic: '30 min — payment recovery + roadmap',
    occurredAt: '2026-05-23T20:00:00Z',
  },
  {
    id: 'cm-003',
    channel: 'in_app',
    with: 'Sequoia Senior Living — Vita K.',
    topic: 'Feature request — bed availability widget',
    occurredAt: '2026-05-23T18:45:00Z',
  },
];

export const OWNER_AUDIT: readonly OwnerAuditEntry[] = [
  {
    id: 'au-001',
    actor: 'avery@bahg.org',
    action: 'Created user',
    target: 'jordan@bahg.org',
    occurredAt: '2026-05-24T16:00:00Z',
    ipAddress: '203.0.113.18',
  },
  {
    id: 'au-002',
    actor: 'admin@wemarketplus.com',
    action: 'Reset password',
    target: 'lana@northstar.org',
    occurredAt: '2026-05-23T22:14:00Z',
    ipAddress: '198.51.100.5',
  },
  {
    id: 'au-003',
    actor: 'avery@bahg.org',
    action: 'Exported HIPAA log',
    target: 'May 2026 bundle',
    occurredAt: '2026-05-23T17:30:00Z',
    ipAddress: '203.0.113.18',
  },
];
