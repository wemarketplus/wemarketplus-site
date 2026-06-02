// index.html CommunityLink pricing — single "per facility" plans (Pro / Gold /
// Max), verbatim from the live site.
import type { PlanTone } from './hospicePricingPlans';

export type CommunityPlanIcon = 'activity' | 'star' | 'pointer';

export interface CommunityPlan {
  eyebrow: string;
  subtitle: string;
  tone: PlanTone;
  icon: CommunityPlanIcon;
  popular?: boolean;
  price: string;
  users: string;
  features: readonly string[];
  demoLabel: string;
  demoHref: string;
}

export const COMMUNITYLINK_PLANS: readonly CommunityPlan[] = [
  {
    eyebrow: 'CommunityLink Pro',
    subtitle: 'Sales & Outreach',
    tone: 'azure',
    icon: 'activity',
    price: '$499',
    users: 'Up to 5 users',
    demoLabel: 'View Pro Demo',
    demoHref: '/demo/communitylink/pro',
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
    icon: 'star',
    popular: true,
    price: '$999',
    users: 'Up to 15 users',
    demoLabel: 'View Gold Demo',
    demoHref: '/demo/communitylink/gold',
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
    icon: 'pointer',
    price: '$1,999',
    users: 'Up to 30 users',
    demoLabel: 'View Max Demo',
    demoHref: '/demo/communitylink/max',
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
