import type { PillProps } from '@/shared/ui/data-display';
import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import type { ReferralFormValues } from '../schema/clReferralSchema';

export const CL_REFERRALS_PAGE_SIZE = 20;

// Referral source `type` is a free-form varchar on the backend; the UI offers a
// stable set of buckets (matching the CommunityLink referral-partners screen).
export const REFERRAL_TYPE = {
  Physician: 'physician',
  Hospital: 'hospital',
  SocialWorker: 'social_worker',
  RehabSnf: 'rehab_snf',
  Community: 'community',
} as const;
export type ReferralType = (typeof REFERRAL_TYPE)[keyof typeof REFERRAL_TYPE];

export const REFERRAL_TYPE_LABELS: Record<string, string> = {
  [REFERRAL_TYPE.Physician]: 'Physician',
  [REFERRAL_TYPE.Hospital]: 'Hospital',
  [REFERRAL_TYPE.SocialWorker]: 'Social Worker',
  [REFERRAL_TYPE.RehabSnf]: 'Rehab / SNF',
  [REFERRAL_TYPE.Community]: 'Community',
};

// Label for an arbitrary stored type: known slug -> label, else the raw value.
export function referralTypeLabel(type: string | null): string {
  if (!type) return '—';
  return REFERRAL_TYPE_LABELS[type] ?? type;
}

export const REFERRAL_TYPE_PILL: Record<string, PillProps['tone']> = {
  [REFERRAL_TYPE.Physician]: 'b',
  [REFERRAL_TYPE.Hospital]: 'p',
  [REFERRAL_TYPE.SocialWorker]: 'y',
  [REFERRAL_TYPE.RehabSnf]: 'g',
  [REFERRAL_TYPE.Community]: 'b',
};

export const REFERRAL_TYPE_OPTIONS: readonly EntitySelectOption[] = Object.entries(
  REFERRAL_TYPE_LABELS,
).map(([value, label]) => ({ value, label }));

// Create/edit form field descriptors (drive EntityFormModal). Mirrors the
// "Add Referral Source" screen: Contact Name*, Organization, Type, Phone,
// Email, City, Notes.
export const REFERRAL_FIELDS: ReadonlyArray<EntityField<ReferralFormValues>> = [
  { name: 'name', label: 'Contact name', placeholder: 'Dr. Amanda Chen' },
  { name: 'organization', label: 'Organization', placeholder: 'Dallas Medical Group' },
  { name: 'type', label: 'Type', type: 'select', options: REFERRAL_TYPE_OPTIONS },
  { name: 'phone', label: 'Phone', type: 'tel', placeholder: '(214) 555-0100' },
  { name: 'email', label: 'Email', type: 'email', placeholder: 'name@org.com' },
  { name: 'address', label: 'City', placeholder: 'Dallas' },
  {
    name: 'notes',
    label: 'Notes',
    type: 'textarea',
    full: true,
    placeholder: 'How we met, relationship notes…',
  },
];
