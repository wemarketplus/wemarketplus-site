// index.html #pricing — HospiceLink plan cards, verbatim from the live site.
export type PlanTone = 'azure' | 'sage' | 'amber';

export interface PlanTierRow {
  users: string;
  price: string;
}

export interface PricingPlan {
  badge: string;
  tone: PlanTone;
  variant: 'default' | 'featured' | 'premium';
  name: string;
  startingAt?: string;
  tagline: string;
  blurb: string;
  features: readonly string[];
  rows: readonly PlanTierRow[];
  demoLabel: string;
  demoHref: string;
}

export const HOSPICELINK_PLANS: readonly PricingPlan[] = [
  {
    badge: 'Starter',
    tone: 'azure',
    variant: 'default',
    name: 'HospiceLink Pro',
    startingAt: 'Starting at $149/mo',
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
    rows: [
      { users: '0–5 Users', price: '$149' },
      { users: '5–10 Users', price: '$249' },
      { users: '10–20 Users', price: '$349' },
      { users: 'Unlimited Users', price: '$449' },
    ],
    demoLabel: 'View Pro Demo',
    demoHref: '/demo/hospicelink/pro',
  },
  {
    badge: 'Professional',
    tone: 'sage',
    variant: 'featured',
    name: 'HospiceLink Max',
    startingAt: 'Starting at $449/mo',
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
    rows: [
      { users: '0–10 Users', price: '$449' },
      { users: '10–20 Users', price: '$649' },
      { users: 'Unlimited Users', price: '$849' },
    ],
    demoLabel: 'View Max Demo',
    demoHref: '/demo/hospicelink/max',
  },
  {
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
    rows: [
      { users: '0–10 Users', price: '$749' },
      { users: '10–20 Users', price: '$999' },
      { users: 'Unlimited Users', price: '$1,299' },
    ],
    demoLabel: 'View Gold Demo',
    demoHref: '/demo/hospicelink/gold',
  },
];
