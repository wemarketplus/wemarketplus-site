// index.html CommunityLink pricing — single "per facility" plans (Pro / Gold /
// Max), verbatim from the live site.
import type { PlanTone } from './hospicePricingPlans';

export interface CommunityPlan {
  eyebrow: string;
  subtitle: string;
  tone: PlanTone;
  popular?: boolean;
  price: string;
  users: string;
  features: readonly string[];
}

export const COMMUNITYLINK_PLANS: readonly CommunityPlan[] = [
  {
    eyebrow: 'CommunityLink Pro',
    subtitle: 'Sales & Outreach',
    tone: 'azure',
    price: '$499',
    users: 'Up to 5 users',
    features: [
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
    eyebrow: 'CommunityLink Gold',
    subtitle: 'Sales + Operations',
    tone: 'amber',
    popular: true,
    price: '$999',
    users: 'Up to 15 users',
    features: [
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
    eyebrow: 'CommunityLink Max',
    subtitle: 'Sales + Operations + Financial',
    tone: 'sage',
    price: '$1,999',
    users: 'Up to 30 users',
    features: [
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
