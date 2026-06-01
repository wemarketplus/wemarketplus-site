import { Product, Tier } from '@/shared/types';
import type {
  MarketingFeature,
  MarketingTierCard,
} from '../types/marketingTypes';

// HospiceLink tiers — prices + features verbatim from index.html #pricing.
// Pricing is per-month at the entry user band; the page lists higher bands
// (5–10 / 10–20 / Unlimited) which we surface as the `bands` note.
export const HOSPICELINK_TIERS: readonly MarketingTierCard[] = [
  {
    tier: Tier.Pro,
    product: Product.HospiceLink,
    name: 'HospiceLink Pro',
    tagline: 'Get organized — stop losing referrals to spreadsheets.',
    monthlyPrice: 149,
    perSeat: false,
    bands: '0–5 users · scales to $449/mo unlimited',
    highlights: [
      'Complete prospect pipeline — Inquiry to Admitted',
      'Referral source management with status tracking',
      'Follow-up reminders auto-set from due dates',
      'Weekly report emailed every Monday at 7am',
      'AI Assistant available 24/7',
      'One-click CSV importer',
      'Referral Portal & BAA included',
    ],
  },
  {
    tier: Tier.Max,
    product: Product.HospiceLink,
    name: 'HospiceLink Max',
    tagline: 'Grow your referrals — full team, full visibility.',
    monthlyPrice: 449,
    perSeat: false,
    bands: '0–10 users · scales to $849/mo unlimited',
    featured: true,
    highlights: [
      'Everything in Pro',
      'EVV / GPS mileage & compliance log',
      'Territory Heat Map with ZIP color-coding',
      '14-Day Cold Source Alerts',
      'AI Playbook Generator',
      'Family Communication Log',
      'Admin & Marketer roles',
    ],
  },
  {
    tier: Tier.Gold,
    product: Product.HospiceLink,
    name: 'HospiceLink Gold',
    tagline: 'Dominate your territory — the complete command center.',
    monthlyPrice: 749,
    perSeat: false,
    bands: '0–10 users · scales to $1,299/mo unlimited',
    highlights: [
      'Everything in Max',
      'Windshield Voice Mode',
      'Revenue Intelligence & forecasting',
      'AI Referral Triage (1–10 scoring)',
      'Telehealth & Patient Portal',
      'Nurse Scheduling Engine',
      'HIPAA Audit Log',
      'Aircall — Call, Text & Email from CRM',
      '4-role access: Admin, Marketer, Nurse, Caregiver',
    ],
  },
];

// CommunityLink tiers — per-facility pricing from index.html #cl-pricing.
export const COMMUNITYLINK_TIERS: readonly MarketingTierCard[] = [
  {
    tier: Tier.Pro,
    product: Product.CommunityLink,
    name: 'CommunityLink Pro',
    tagline: 'Sales & outreach for a single community.',
    monthlyPrice: 499,
    perSeat: false,
    bands: 'Per facility · up to 5 users',
    highlights: [
      'Lead CRM & prospect pipeline',
      'Tour scheduling & follow-ups',
      'Referral source CRM',
      'GPS outreach check-in',
      'Mileage tracker',
      'Director of Sales dashboard',
      'Marketer dashboard',
      'AI sales assistant',
    ],
  },
  {
    tier: Tier.Gold,
    product: Product.CommunityLink,
    name: 'CommunityLink Gold',
    tagline: 'Sales + operations in one console.',
    monthlyPrice: 999,
    perSeat: false,
    bands: 'Per facility · up to 15 users',
    featured: true,
    highlights: [
      'Everything in Pro',
      'Apartment inventory system',
      'Make-ready workflow',
      'Maintenance dashboard',
      'Housekeeping dashboard',
      'Executive Director view',
      'Task management & checklists',
      'AI operations assistant',
    ],
  },
  {
    tier: Tier.Max,
    product: Product.CommunityLink,
    name: 'CommunityLink Max',
    tagline: 'The full command center for a portfolio.',
    monthlyPrice: 1999,
    perSeat: false,
    bands: 'Per facility · up to 30 users',
    highlights: [
      'Everything in Gold',
      'Owner/Investor dashboard',
      'Financial ledger & revenue tracking',
      'LOC pricing calculator',
      'Revenue leakage tracker',
      'Concession approval workflow',
      'Competitor benchmarking',
      'Aircall — Call, Text & Email from CRM',
      'Portfolio analytics',
    ],
  },
];

export const HOSPICELINK_FEATURES: readonly MarketingFeature[] = [
  {
    title: 'Prospect & referral pipeline',
    description:
      'A single source of truth for everyone in your agency — no more spreadsheets.',
  },
  {
    title: 'AI assistant',
    description:
      'Drafts follow-ups, scores prospects, and surfaces cold sources before you ask.',
  },
  {
    title: 'Field-ready mobile',
    description:
      'GPS check-in, mileage capture, and a windshield-mode view marketers actually use.',
  },
  {
    title: 'HIPAA from day one',
    description:
      'Audit log, BAA flow, role-based access, and encryption at rest baked in.',
  },
];

export const COMMUNITYLINK_FEATURES: readonly MarketingFeature[] = [
  {
    title: 'Lead pipeline → move-in',
    description:
      'Track inquiries through tours, proposals, and move-in without losing a beat.',
  },
  {
    title: 'Operations command',
    description:
      'Apartments, make-ready, maintenance, and housekeeping in one console.',
  },
  {
    title: 'Revenue intelligence',
    description:
      'See where revenue leaks, where concessions stack up, and where occupancy is going.',
  },
  {
    title: 'Built for community teams',
    description:
      'Designed for sales counselors, executive directors, and maintenance leads.',
  },
];
