import {
  MessagesSquare,
  Phone,
  Stethoscope,
  Video,
  Activity,
  Users,
  ClipboardList,
} from 'lucide-react';
import type { ClinicalFeature } from '../types/clinicalTypes';

// Mirrors the site's Gold-tier "Clinical" sidebar entries — each is a thin
// landing page describing the feature with a CTA, since the actual backend
// integrations (Twilio messaging, telehealth provider, EVV vendor) are not
// wired yet.
export const CLINICAL_FEATURES: readonly ClinicalFeature[] = [
  {
    id: 'family-communication',
    title: 'Family communication',
    description:
      'Reach family members across call, text, and email from one thread.',
    icon: MessagesSquare,
    status: 'available',
  },
  {
    id: 'secure-messaging',
    title: 'Secure messaging',
    description: 'HIPAA-compliant inbound and outbound messaging.',
    icon: MessagesSquare,
    status: 'available',
  },
  {
    id: 'admission-workflow',
    title: 'Admission workflow',
    description: 'A structured intake-to-admit checklist with audit trail.',
    icon: ClipboardList,
    status: 'available',
  },
  {
    id: 'evv-mileage',
    title: 'EVV / mileage',
    description: 'Electronic visit verification plus mileage capture for compliance.',
    icon: Activity,
    status: 'beta',
  },
  {
    id: 'telehealth',
    title: 'Telehealth',
    description: 'In-app video visits with families and primary care.',
    icon: Video,
    status: 'coming_soon',
  },
  {
    id: 'aircall',
    title: 'Aircall phone',
    description: 'Make calls and SMS from the CRM without leaving the tab.',
    icon: Phone,
    status: 'available',
  },
  {
    id: 'nurse-scheduler',
    title: 'Nurse scheduler',
    description: 'Coordinate RN visits across the team with conflict detection.',
    icon: Stethoscope,
    status: 'beta',
  },
  {
    id: 'patient-portal',
    title: 'Patient portal',
    description: 'Lightweight portal for patients and families to view care updates.',
    icon: Users,
    status: 'coming_soon',
  },
];

export const STATUS_LABEL: Record<ClinicalFeature['status'], string> = {
  available: 'Available',
  beta: 'Beta',
  coming_soon: 'Coming soon',
};

export const STATUS_TONE: Record<ClinicalFeature['status'], string> = {
  available: 'border-success/30 bg-success/10 text-success',
  beta: 'border-warning/30 bg-warning/10 text-warning',
  coming_soon: 'border-white/[0.08] bg-white/[0.03] text-muted-soft',
};
