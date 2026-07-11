import type { PillProps } from '@/shared/ui/data-display';
import type { EntityField, EntitySelectOption } from '@/shared/ui/entity';
import {
  CL_CARE_LEVEL,
  CL_LEAD_STAGE,
  CL_URGENCY,
  type ClCareLevel,
  type ClLeadStage,
  type ClUrgency,
} from './clLeadApiConstants';
import type { LeadFormValues } from '../schema/leadSchema';

export const CL_LEADS_PAGE_SIZE = 20;

// --- Display labels (backend enums -> human copy) --------------------------

export const CARE_LEVEL_LABELS: Record<ClCareLevel, string> = {
  [CL_CARE_LEVEL.IndependentLiving]: 'Independent Living',
  [CL_CARE_LEVEL.AssistedLiving]: 'Assisted Living',
  [CL_CARE_LEVEL.MemoryCare]: 'Memory Care',
};

export const LEAD_STAGE_LABELS: Record<ClLeadStage, string> = {
  [CL_LEAD_STAGE.Inquiry]: 'Inquiry',
  [CL_LEAD_STAGE.Contacted]: 'Contacted',
  [CL_LEAD_STAGE.TourScheduled]: 'Tour scheduled',
  [CL_LEAD_STAGE.Toured]: 'Toured',
  [CL_LEAD_STAGE.ProposalSent]: 'Proposal sent',
  [CL_LEAD_STAGE.DepositPaid]: 'Deposit paid',
  [CL_LEAD_STAGE.MovedIn]: 'Moved in',
  [CL_LEAD_STAGE.Lost]: 'Lost',
  [CL_LEAD_STAGE.Inactive]: 'Inactive',
};

export const URGENCY_LABELS: Record<ClUrgency, string> = {
  [CL_URGENCY.Hot]: 'Hot',
  [CL_URGENCY.Warm]: 'Warm',
  [CL_URGENCY.Cold]: 'Cold',
};

export const STAGE_PILL: Record<ClLeadStage, PillProps['tone']> = {
  [CL_LEAD_STAGE.Inquiry]: 'b',
  [CL_LEAD_STAGE.Contacted]: 'b',
  [CL_LEAD_STAGE.TourScheduled]: 'p',
  [CL_LEAD_STAGE.Toured]: 'p',
  [CL_LEAD_STAGE.ProposalSent]: 'y',
  [CL_LEAD_STAGE.DepositPaid]: 'y',
  [CL_LEAD_STAGE.MovedIn]: 'g',
  [CL_LEAD_STAGE.Lost]: 'r',
  [CL_LEAD_STAGE.Inactive]: 'r',
};

export const URGENCY_PILL: Record<ClUrgency, PillProps['tone']> = {
  [CL_URGENCY.Hot]: 'r',
  [CL_URGENCY.Warm]: 'y',
  [CL_URGENCY.Cold]: 'b',
};

// --- Select option lists (reused by the form + the pipeline filters) -------

const toOptions = (labels: Record<string, string>): readonly EntitySelectOption[] =>
  Object.entries(labels).map(([value, label]) => ({ value, label }));

export const CARE_LEVEL_OPTIONS = toOptions(CARE_LEVEL_LABELS);
export const STAGE_OPTIONS = toOptions(LEAD_STAGE_LABELS);
export const URGENCY_OPTIONS = toOptions(URGENCY_LABELS);

// --- Create/edit form field descriptors (drive EntityFormModal) ------------

export const LEAD_FIELDS: ReadonlyArray<EntityField<LeadFormValues>> = [
  { name: 'fullName', label: 'Full name', full: true, placeholder: 'Dorothy Harrison' },
  { name: 'phone', label: 'Phone', type: 'tel', placeholder: '(214) 555-0100' },
  { name: 'email', label: 'Email', type: 'email', placeholder: 'name@example.com' },
  { name: 'careLevel', label: 'Care level', type: 'select', options: CARE_LEVEL_OPTIONS },
  { name: 'stage', label: 'Stage', type: 'select', options: STAGE_OPTIONS },
  { name: 'urgency', label: 'Urgency', type: 'select', options: URGENCY_OPTIONS },
  { name: 'source', label: 'Referral source', placeholder: 'Website, Physician Referral…' },
  { name: 'followUpDate', label: 'Follow-up date', type: 'date' },
  { name: 'notes', label: 'Notes', type: 'textarea', full: true, placeholder: 'Key details, family contacts, budget…' },
];
