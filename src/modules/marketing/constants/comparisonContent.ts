// Full Feature Comparison matrix — verbatim from index.html #pricing.
import type { ComparisonRow } from '../types/comparisonTypes';

export const HOSPICE_COMPARISON: readonly ComparisonRow[] = [
  { feature: 'Prospect Pipeline', pro: true, max: true, gold: true },
  { feature: 'AI Assistant', pro: true, max: true, gold: true },
  { feature: 'Weekly Report (auto-email)', pro: true, max: true, gold: true },
  { feature: 'CSV Import', pro: true, max: true, gold: true },
  { feature: '14-Day Cold Alerts', pro: false, max: true, gold: true },
  { feature: 'EVV / GPS Mileage', pro: false, max: true, gold: true },
  { feature: 'Territory Heat Map', pro: false, max: false, gold: true },
  { feature: 'AI Playbook Generator', pro: false, max: true, gold: true },
  { feature: 'Windshield Voice Mode', pro: false, max: false, gold: true },
  { feature: 'Revenue Intelligence', pro: false, max: false, gold: true },
  { feature: 'AI Referral Triage', pro: false, max: false, gold: true },
  { feature: 'HIPAA Audit Log', pro: false, max: false, gold: true },
  { feature: 'Telehealth & Patient Portal', pro: false, max: false, gold: true },
  { feature: 'Nurse & Caregiver Roles', pro: false, max: false, gold: true },
  { feature: 'Aircall — Call, Text & Email', pro: false, max: false, gold: true },
];
