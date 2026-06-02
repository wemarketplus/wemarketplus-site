// Verbatim landing-page copy ported from wemarketplus-site/index.html.
// Kept as data so the section components stay thin and presentational.
import type {
  CommunityPillar,
  CommunityTile,
  Faq,
  FeatureCard,
  HowStep,
  Metric,
  SecurityCard,
  Testimonial,
  TrustBadge,
} from '../types/landingTypes';

export const HERO = {
  eyebrow: '🏥 Purpose-Built for Hospice · HIPAA-Ready Day One',
  title: 'Your next 5 admits are\n hiding in a spreadsheet.',
  titleAccent: 'We help you find them.',
  subheading:
    'The only CRM built exclusively for hospice marketers. Every referral tracked, every follow-up automated, every admit captured — live in 30 minutes, HIPAA-ready from day one.',
  proofPoints: [
    'HIPAA-Ready & BAA Included',
    'No Setup Fee — Live in 30 Min',
    '30-Day Money-Back Guarantee',
    'Built for Hospice Only',
  ],
} as const;

export const METRICS: readonly Metric[] = [
  { value: '47+', label: 'Hospice Teams', tone: 'sage' },
  { value: '40%', label: 'Avg Admit Lift', tone: 'azure' },
  { value: '$0', label: 'Setup Fee', tone: 'amber' },
  { value: '24/7', label: 'AI Assistant', tone: 'purple' },
  { value: '30-Day', label: 'Guarantee', tone: 'sage' },
];

export const HOSPICE_FEATURE_CARDS: readonly FeatureCard[] = [
  {
    title: 'Prospect Pipeline',
    body: 'Inquiry to Admitted. Every prospect tracked, every follow-up auto-queued. No referral falls through the cracks.',
    badge: 'All Plans',
    tone: 'azure',
    icon: 'pipeline',
  },
  {
    title: '14-Day Cold Source Alerts',
    body: 'Know which referral sources are going cold before they stop sending. Automated alerts with one-click resolution.',
    badge: 'Max + Gold',
    tone: 'red',
    icon: 'alert',
  },
  {
    title: 'Territory Heat Map',
    body: 'Visual ZIP code referral density. Identify hot zones, untapped territories, and routing inefficiencies instantly.',
    badge: 'Max + Gold',
    tone: 'sage',
    icon: 'map',
  },
  {
    title: 'AI Assistant',
    body: '24/7 hospice marketing intelligence. Draft follow-up scripts, identify cold sources, convert more pending admits.',
    badge: 'All Plans',
    tone: 'purple',
    icon: 'ai',
  },
  {
    title: 'EVV / GPS Mileage',
    body: 'GPS-verified visit log with IRS-rate mileage reimbursement. Auto-syncs to weekly payroll reports.',
    badge: 'Max + Gold',
    tone: 'sage',
    icon: 'mileage',
  },
  {
    title: 'Windshield Mode',
    body: 'Voice-to-note while driving. Tap once, speak, auto-transcribed and GPS-stamped. Zero typing required.',
    badge: 'Gold Only',
    tone: 'amber',
    icon: 'windshield',
  },
  {
    title: 'Revenue Intelligence',
    body: 'Cost per admission, revenue per source, team ROI. Know exactly what your marketing investment generates.',
    badge: 'Gold Only',
    tone: 'amber',
    icon: 'revenue',
  },
  {
    title: 'AI Referral Triage',
    body: 'Incoming referrals scored 1–10 by conversion probability. Act before your competitors even return the call.',
    badge: 'Gold Only',
    tone: 'amber',
    icon: 'triage',
  },
  {
    title: 'HIPAA Audit Log',
    body: 'Every action logged with timestamp, user, and IP address. Full compliance trail for Joint Commission readiness.',
    badge: 'Gold Only',
    tone: 'amber',
    icon: 'audit',
  },
  {
    title: 'Aircall — Call, Text & Email',
    body: 'Reach referral sources and prospects directly from the CRM. One-click calls, templated texts, tracked emails — all auto-logged to the HIPAA audit trail.',
    badge: 'Gold Only',
    tone: 'amber',
    icon: 'phone',
  },
];

export const HOW_IT_WORKS: readonly HowStep[] = [
  {
    num: '01',
    title: 'Subscribe & Sign BAA',
    body: 'Choose your plan and sign the HIPAA Business Associate Agreement at checkout. Your account is live immediately.',
  },
  {
    num: '02',
    title: 'Import Your Prospects',
    body: 'Upload your existing spreadsheet via one-click CSV importer. Done in minutes with automatic column mapping.',
  },
  {
    num: '03',
    title: 'Add Referral Sources',
    body: 'Set follow-up cadences and cold-alert timers. Never let a referral relationship go cold again.',
  },
  {
    num: '04',
    title: 'Close More Admits',
    body: 'Follow reminders, act on cold alerts, use AI insights, and watch your census climb. Most teams see results within 48 hours.',
  },
];

export const TESTIMONIALS: readonly Testimonial[] = [
  {
    name: 'Maria T.',
    role: 'Marketing Director, Dallas TX',
    quote:
      'HospiceLink cut our response time from 3 days to under 18 hours. The cold-source alerts alone changed how we operate as an organization.',
  },
  {
    name: 'Sandra M.',
    role: 'Regional Director, Houston TX',
    quote:
      'Referrals tripled in two months. We recovered 9 lost prospects in the first month and admitted 3 of them. The ROI was immediate and measurable.',
  },
  {
    name: 'David K.',
    role: 'Executive Director, Austin TX',
    quote:
      'Finally a CRM that speaks hospice — not HubSpot with a new skin. My team went from 5 admits per month to 9 in just 6 weeks.',
  },
];

export const SECURITY_CARDS: readonly SecurityCard[] = [
  { title: 'TLS 1.3 Encryption', body: 'All data encrypted in transit and at rest. Zero plaintext storage of PHI.', icon: 'encryption' },
  { title: 'BAA at Checkout', body: 'Business Associate Agreement executed for every plan on signup.', icon: 'baa' },
  { title: 'Role-Based Access', body: 'Seat-cap enforcement, admin controls, and server-side validation throughout.', icon: 'roles' },
  { title: 'HIPAA Audit Log', body: 'Every PHI access logged with timestamp, user, and IP. Gold tier.', icon: 'audit' },
  { title: '99.9% Uptime SLA', body: 'Enterprise cloud infrastructure. Public status page available 24/7.', icon: 'uptime' },
  { title: '30-Day Guarantee', body: 'Not satisfied within 30 days? Full refund, no questions, no delays.', icon: 'guarantee' },
];

export const FAQS: readonly Faq[] = [
  {
    q: 'Is HospiceLink HIPAA compliant?',
    a: 'Yes. TLS 1.3 encryption in transit, AES-256 at rest, and a Business Associate Agreement (BAA) is executed at checkout for all plan tiers.',
  },
  {
    q: 'How long does setup take?',
    a: 'Most teams are fully operational within 30 minutes. Subscribe, sign the BAA, import your existing prospects via CSV, and start logging notes. No IT or configuration required.',
  },
  {
    q: 'Can I import my existing spreadsheet?',
    a: 'Yes. Use the one-click CSV importer to bring in all your existing prospects. The importer maps common column names automatically.',
  },
  {
    q: 'What roles are included?',
    a: 'Pro and Max include Admin and Marketer roles. Gold adds Nurse and Caregiver roles with tailored dashboards for each.',
  },
  {
    q: 'What is the 30-day money-back guarantee?',
    a: 'If you are not satisfied within the first 30 days, email us for a full refund. No questions asked, no lengthy cancellation process.',
  },
  {
    q: 'Can I cancel at any time?',
    a: 'Yes. Cancel from your billing portal at any time. No contracts, no cancellation fees, no minimum commitments.',
  },
  {
    q: 'Is there a setup fee?',
    a: 'No. There is no setup fee on any plan. Your subscription price is exactly what you pay at signup.',
  },
  {
    q: 'Do you offer annual pricing?',
    a: 'Yes. Annual plans include a discount. Email info@wemarketplus.com for annual pricing options.',
  },
];

export const COMMUNITY_PILLARS: readonly CommunityPillar[] = [
  {
    icon: 'sales',
    title: 'Sales + Outreach CRM',
    body: 'Track leads, referral sources, tours, and follow-ups. GPS check-ins, mileage logging, and competitor benchmarking built in.',
    tone: 'amber',
  },
  {
    icon: 'operations',
    title: 'Make-Ready + Operations',
    body: 'Apartment inventory, make-ready workflows, maintenance ticketing, and housekeeping task management all synced in real time.',
    tone: 'sage',
  },
  {
    icon: 'financial',
    title: 'Financial Command Center',
    body: 'Revenue tracking, concession approvals, LOC pricing calculator, revenue leakage detection, and investor-ready reports.',
    tone: 'azure',
  },
];

export const COMMUNITY_TILES: readonly CommunityTile[] = [
  { icon: '🏠', title: 'Apartment Inventory', body: 'Track every unit — available, occupied, on-notice, make-ready, and reserved.' },
  { icon: '📋', title: 'Make-Ready Workflow', body: 'Assign tasks across maintenance and housekeeping. Track completion stage by stage.' },
  { icon: '👥', title: 'Lead CRM', body: 'Full prospect pipeline from inquiry to move-in with follow-up automation and tour scheduling.' },
  { icon: '📍', title: 'GPS Outreach', body: 'Log field visits with GPS check-in, mileage tracking, and referral source management.' },
  { icon: '💰', title: 'Financial Ledger', body: 'Revenue tracking, concession approvals, LOC pricing, and revenue leakage detection.' },
  { icon: '📊', title: 'Investor Reports', body: 'Owner and investor dashboards with portfolio-level performance, occupancy, and revenue metrics.' },
  { icon: '🏆', title: 'Competitor Intel', body: 'Log competitor rates, amenities, and promotions. Stay ahead of the market.' },
  { icon: '🔧', title: 'Maintenance Tickets', body: 'Resident-reported and staff-created maintenance requests with priority routing and SLA tracking.' },
];

export const TRUST_BADGES: readonly TrustBadge[] = [
  { icon: 'shield', tone: 'sage', title: 'HIPAA Compliant', sub: 'TLS 1.3 · AES-256' },
  { icon: 'lock', tone: 'azure', title: 'BAA Included', sub: 'Signed at checkout' },
  { icon: 'guarantee', tone: 'amber', title: '30-Day Guarantee', sub: 'Full refund, no questions' },
  { icon: 'clock', tone: 'sage', title: 'Live in 30 Minutes', sub: 'No setup fee, no IT' },
  { icon: 'phone', tone: 'azure', title: 'US-Based Support', sub: 'Real humans, fast response' },
];
