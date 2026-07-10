// #pricing — HospiceLink plan cards. Prices mirror the real billing catalog
// (wemarketplus-backend GET /billing/plans): one flat monthly price per tier
// with a fixed seat allowance.
import { COMMUNITYLINK_DEMO_URLS } from '@/shared/config/demoUrls';

export type PlanTone = 'azure' | 'sage' | 'amber';

export interface PlanTierRow {
  users: string;
  price: string;
}

export interface PricingPlan {
  // Backend billing catalog key (POST /billing/checkout { planKey }). See
  // wemarketplus-backend/src/billing/plan-catalog.ts.
  planKey: string;
  badge: string;
  tone: PlanTone;
  variant: 'default' | 'featured' | 'premium';
  name: string;
  tagline: string;
  blurb: string;
  features: readonly string[];
  rows: readonly PlanTierRow[];
  demoLabel: string;
  demoHref: string;
}

export const HOSPICELINK_PLANS: readonly PricingPlan[] = [
  {
    planKey: 'hl_pro',
    badge: 'Starter',
    tone: 'azure',
    variant: 'default',
    name: 'HospiceLink Pro',
    tagline: 'Get organized — stop losing referrals to spreadsheets',
    blurb:
      'Complete prospect profiles, referral source management, follow-up reminders, AI assistant, and weekly reports. Most users see improvement within 48 hours.',
    features: [
      'Complete prospect pipeline — Inquiry to Admitted',
      'Referral source management with status tracking',
      'Follow-up reminders auto-set from due dates',
      'Weekly report emailed every Monday at 7am',
      'AI Assistant available 24/7',
      'One-click CSV importer',
      'Referral Portal & BAA included',
    ],
    rows: [{ users: 'Up to 5 users included', price: '$149' }],
    demoLabel: 'View Pro Demo',
    demoHref: COMMUNITYLINK_DEMO_URLS.pro,
  },
  {
    planKey: 'hl_max',
    badge: 'Professional',
    tone: 'sage',
    variant: 'featured',
    name: 'HospiceLink Max',
    tagline: 'Grow your referrals — full team, full visibility',
    blurb:
      'Everything in Pro, plus EVV mileage, 14-day cold alerts, territory heat map, smart scheduling, and AI playbook generation.',
    features: [
      'Everything in Pro',
      'EVV / GPS mileage & compliance log',
      'Territory Heat Map with ZIP color-coding',
      '14-Day Cold Source Alerts',
      'AI Playbook Generator',
      'Family Communication Log',
      'Admin & Marketer roles',
    ],
    rows: [{ users: 'Up to 10 users included', price: '$449' }],
    demoLabel: 'View Max Demo',
    demoHref: COMMUNITYLINK_DEMO_URLS.max,
  },
  {
    planKey: 'hl_gold',
    badge: 'Enterprise',
    tone: 'amber',
    variant: 'premium',
    name: 'HospiceLink Gold',
    tagline: 'Dominate your territory — the complete command center',
    blurb:
      'Everything in Max plus Revenue Intelligence, AI Referral Triage, Windshield Mode, Telehealth, Nurse Scheduling, HIPAA Audit Log, and full 4-role access.',
    features: [
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
    rows: [{ users: 'Up to 10 users included', price: '$749' }],
    demoLabel: 'View Gold Demo',
    demoHref: COMMUNITYLINK_DEMO_URLS.gold,
  },
];
